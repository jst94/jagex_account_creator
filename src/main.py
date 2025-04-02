import configparser
import json
import os
import random
import re
import shutil
import string
import sys
import threading
import time
from pathlib import Path

import pyotp
from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.common import Settings
from DrissionPage.items import ChromiumElement, MixTab
from imap_tools import AND, MailBox
from loguru import logger

from proxies.proxy_extension import create_proxy_extension
from traffic_filter_proxy_server import TrafficFilterProxy

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))


# Custom Exception for teardown scenarios
class RegistrationError(Exception):
    pass

class AccountCreator:
    def __init__(self) -> None:
        self.config = configparser.ConfigParser()
        self.config.read(SCRIPT_DIR / "config.ini")
        self.registration_url = (
            "https://account.jagex.com/en-GB/login/registration-start"
        )
        self.management_url = "https://account.jagex.com/en-GB/manage/profile"
        self.accounts_file = SCRIPT_DIR / "accounts.json"
        self.imap_details = {
            "ip": self.config.get("imap", "ip"),
            "port": self.config.getint("imap", "port"),
            "email": self.config.get("imap", "email"),
            "password": self.config.get("imap", "password"),
        }
        self.domains = self.config.get("account", "domains").split(",")
        self.password = self.config.get("account", "password")
        self.set_2fa = self.config.getboolean("account", "set_2fa")

        self.threads = self.config.getint("default", "threads")
        self.headless = self.config.getboolean("default", "headless")
        self.element_wait_timeout = self.config.getint(
            "default", "element_wait_timeout"
        )

        self.use_proxies = self.config.getboolean("proxies", "enabled")
        if self.use_proxies:
            self.proxies = self.load_proxies(SCRIPT_DIR / "proxies" / "proxies.txt")
            self.proxy_index = random.randint(0, len(self.proxies) - 1)
            self.proxies_lock = threading.Lock()

        self.cache_folder = SCRIPT_DIR / "cache"
        self.cache_folder_lock = threading.Lock()
        self.cache_update_threshold = self.config.getfloat(
            "default", "cache_update_threshold"
        )

        self.urls_to_block = [
            ".ico",
            ".jpg",
            ".png",
            ".gif",
            ".svg",
            ".webp",
            "data:image",
            ".woff",
            ".woff2",
            ".woff2!static",
            ".ttf",
            ".otf",
            ".eot",
            "analytics",
            "tracking",
            "google-analytics",
            ".googleapis.",
            "chargebee",
            "cookiebot",
            "beacon",
        ]

        Settings.set_language("en")

    def get_dir_size(self, directory: Path) -> int:
        """Return the size of a directory"""
        return sum(f.stat().st_size for f in directory.glob("**/*") if f.is_file())

    def load_proxies(self, proxy_file_path: Path) -> list:
        """Loads a list of proxies from a file."""
        with open(proxy_file_path, "r") as file:
            # Read each line from the file and strip newline characters
            return [line.strip() for line in file.readlines()]

    def get_next_proxy(self) -> str:
        """Gets the next proxy from the list, cycling back to the start if necessary."""
        with self.proxies_lock:
            # Get the proxy at the current index
            proxy = self.proxies[self.proxy_index]
            # Update the index to point to the next proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy

    def setup_browser_cache(self, co: ChromiumOptions, run_path: Path) -> None:
        """Copies the primary cache and sets copy for current run."""
        run_number = str(run_path).split("_")[-1]
        logger.info(f"Creating cache folder for run number: {run_number}")
        new_cache_folder = run_path / "cache"
        if os.path.isdir(self.cache_folder):
            with self.cache_folder_lock:
                shutil.copytree(self.cache_folder, new_cache_folder)
        co.set_argument(f"--disk-cache-dir={new_cache_folder}")

    def get_new_browser(
        self, run_path: Path, proxy_extension_path: Path = None
    ) -> Chromium:
        """Creates a new browser tab with temp settings and an open port."""
        co = ChromiumOptions()
        co.auto_port()

        co.mute()
        # co.no_imgs()  # no_imgs() seems to cause cloudflare challenge to infinite loop

        # Disable chrome optimization features to save on bandwidth
        # https://source.chromium.org/chromium/chromium/src/+/main:components/optimization_guide/core/optimization_guide_features.cc;l=49-71
        # TODO: Investigate why this doesn't work. Not sure if its DrissionPage not setting them correctly or a different issue.
        # co.set_argument(
        #     "--disable-features=OptimizationGuideModelDownloading,OptimizationHints,OptimizationHintsFetching,OptimizationHintsFetchingAnonymousDataConsent,OptimizationTargetPrediction"
        # )

        self.setup_browser_cache(co, run_path=run_path)

        co.set_timeouts(self.element_wait_timeout)

        # custom user-agent is only needed for headless but why not make it consistent.
        co.set_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
        )

        if self.headless:
            co.set_argument("--headless=new")
        elif self.config.getboolean("default", "enable_dev_tools"):
            co.set_argument("--auto-open-devtools-for-tabs")

        if proxy_extension_path:
            logger.debug(f"Using proxy extension path: {proxy_extension_path}")
            co.add_extension(path=proxy_extension_path)

        browser = Chromium(addr_or_opts=co)
        return browser

    def get_browser_ip(self, tab: MixTab) -> str:
        """Get the IP address that the browser is using."""
        url = "https://api64.ipify.org/?format=raw"
        if tab.get(url):
            ip = tab.ele("tag:pre").text
            return ip
        else:
            self.teardown(tab, "Couldn't get browser ip!")

    def find_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement:
        """Tries to find an element in the tab."""
        logger.debug(f"Looking for element to click with identifier: {identifier}")

        logger.debug("Waiting for element to be loaded")
        found_element = tab.wait.eles_loaded(identifier)
        if not found_element:
            error_msg = f"Couldn't find loaded element with identifier: {identifier}"
            if teardown:
                self.teardown(tab, error_msg)
            else:
                logger.warning(error_msg)
                return

        logger.debug("Getting element")
        element = tab.ele(identifier)
        logger.debug("Waiting for element to be displayed")
        element.wait.displayed()
        if not element:
            error_msg = f"Couldn't find element with identifier: {identifier}"
            if teardown:
                self.teardown(tab, error_msg)
            else:
                logger.warning(error_msg)

        logger.debug("Returning element")
        return element

    def click_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement:
        element = self.find_element(tab, identifier, teardown)
        if element:
            logger.debug("Clicking element")
            tab.actions.move_to(element).click()
        return element

    def click_and_type(
        self, tab: MixTab, identifier: str, text: str, teardown: bool = True
    ) -> ChromiumElement:
        """Clicks on an element and then types the text."""
        element = self.find_element(tab, identifier, teardown)
        if element:
            logger.debug(f"Clicking element and then typing: {text}")
            tab.actions.move_to(element).click().type(text)
        return element

    # Modified teardown: Raise a specific exception instead of exiting
    def teardown(self, tab: MixTab, exit_status: str) -> None:
        """Logs status and raises an exception to signal failure."""
        logger.error(f"Registration failed: {exit_status}")
        if tab and tab.driver: # Check if tab and driver exist
            try:
                tab.close()
            except Exception as e:
                logger.warning(f"Error closing tab during teardown: {e}")
        raise RegistrationError(exit_status) # Raise exception

    def find_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement | None: # Added None return type hint
        """Tries to find an element in the tab."""
        logger.debug(f"Looking for element with identifier: {identifier}")
        try:
            logger.debug("Waiting for element to be loaded")
            # Use wait.ele_displayed directly as it implies loaded and visible
            element = tab.wait.ele_displayed(identifier, timeout=self.element_wait_timeout)
            if not element:
                raise TimeoutError(f"Element '{identifier}' not displayed within timeout.")

            logger.debug("Returning element")
            return element # Return the found element directly
        except Exception as e:
            error_msg = f"Error finding element '{identifier}': {e}"
            if teardown:
                self.teardown(tab, error_msg)
            else:
                logger.warning(error_msg)
                return None # Return None if not tearing down

    def click_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement | None: # Added None return type hint
        element = self.find_element(tab, identifier, teardown)
        if element:
            try:
                logger.debug(f"Clicking element: {identifier}")
                # DrissionPage recommends using element.click() directly if possible
                element.click()
                # tab.actions.move_to(element).click() # Keep as fallback if direct click fails
            except Exception as e:
                error_msg = f"Error clicking element '{identifier}': {e}"
                if teardown:
                    self.teardown(tab, error_msg)
                else:
                    logger.warning(error_msg)
                    return None # Return None on click failure if not tearing down
        return element # Return element if found, None otherwise or if click failed without teardown

    def click_and_type(
        self, tab: MixTab, identifier: str, text: str, teardown: bool = True
    ) -> ChromiumElement | None: # Added None return type hint
        """Clicks on an element and then types the text."""
        element = self.find_element(tab, identifier, teardown)
        if element:
            try:
                logger.debug(f"Clicking element '{identifier}' and then typing: {'*' * len(text) if 'password' in identifier else text}") # Mask password
                # Combine actions for efficiency if possible, or ensure element is ready
                element.click() # Ensure focus
                element.input(text) # Use input for typing
                # tab.actions.move_to(element).click().type(text) # Keep as fallback
            except Exception as e:
                error_msg = f"Error clicking/typing in element '{identifier}': {e}"
                if teardown:
                    self.teardown(tab, error_msg)
                else:
                    logger.warning(error_msg)
                    return None # Return None on type failure if not tearing down
        return element # Return element if found, None otherwise or if type failed without teardown

    def check_for_challenge(self, tab: MixTab) -> bool:
        """Checks if we got a CF challenge on the page."""
        return tab.wait.ele_displayed("#challenge-form", timeout=5)

    def locate_cf_button(self, tab: MixTab) -> ChromiumElement:
        """Finds the CF challenge button in the tab. Credit to CloudflareBypasser."""
        button = None
        checkbox_wait_seconds = 5
        logger.info(
            f"sleeping {checkbox_wait_seconds} seconds before getting CF checkbox"
        )
        time.sleep(checkbox_wait_seconds)
        eles = tab.eles("tag:input")
        for ele in eles:
            if "name" in ele.attrs.keys() and "type" in ele.attrs.keys():
                if "turnstile" in ele.attrs["name"] and ele.attrs["type"] == "hidden":
                    return (
                        ele.parent()
                        .shadow_root.child()("tag:body")
                        .shadow_root("tag:input")
                    )
        return button

    def bypass_challenge(self, tab: MixTab) -> bool:
        """Attempts to bypass the CF challenge by clicking the checkbox."""
        sleep_seconds = 2
        max_retries = 2
        retry_count = 0

        # Poll for the CF challenge button, with a maximum retry count
        while retry_count < max_retries:
            button = self.locate_cf_button(tab)
            if button:
                logger.debug("Found CF challenge button. Clicking.")
                button.click()
                return tab.wait.title_change("Create a Jagex account", timeout=15)

            logger.warning(
                f"Couldn't find CF challenge button. Retrying in {sleep_seconds} seconds."
            )
            time.sleep(sleep_seconds)
            retry_count += 1

        logger.error("Max retries reached. Failed to find CF challenge button.")
        return False

    def generate_username(self, length: int = 10) -> str:
        """Generates a unique string based on length provided."""
        characters = string.ascii_letters + string.digits
        username = "".join(random.choice(characters.lower()) for _ in range(length))
        logger.debug(f"Returning generated username: {username} of length: {length}")
        return username

    def get_account_domain(self) -> str:
        """Gets a random domain to use for verification."""
        index = random.randint(0, len(self.domains) - 1)
        return self.domains[index]

    def _get_verification_code(self, tab: MixTab, account_email: str) -> str:
        """Gets the verification code from catch all email via imap"""
        logger.info(f"Attempting to retrieve verification code for {account_email}")
        email_query = AND(to=account_email, seen=False)
        # Consider making regex slightly more robust if format changes
        code_regex = r'data-testid="registration-started-verification-code"[^>]*>([A-Z0-9]+)<'
        mailbox = None
        try:
            # Use context manager for MailBox connection
            with MailBox(self.imap_details["ip"], self.imap_details["port"]).login(
                self.imap_details["email"], self.imap_details["password"], initial_folder='INBOX' # Specify inbox
            ) as mailbox:
                # Increased timeout slightly, consider making configurable
                for i in range(self.element_wait_timeout * 12): # e.g. 120 seconds if timeout is 10
                    logger.debug(f"Checking email attempt {i+1}...")
                    # Fetch unseen emails matching the recipient
                    emails = list(mailbox.fetch(email_query, limit=5, mark_seen=False)) # Keep unseen, limit fetch
                    if not emails:
                        logger.debug("No matching emails found yet.")
                    for email in emails:
                        logger.debug(f"Found email: Subject='{email.subject}', From='{email.from_}', To='{email.to}'")
                        # Check HTML content for the code
                        if email.html:
                            match = re.search(code_regex, email.html)
                            if match:
                                code = match.group(1)
                                logger.info(f"Found verification code: {code}")
                                # Mark this specific email as seen after finding code
                                mailbox.flag([email.uid], '\\Seen', True)
                                return code
                        else:
                            logger.warning(f"Email UID {email.uid} has no HTML content.")
                    time.sleep(1) # Wait 1 second between checks
            # If loop finishes without finding code
            self.teardown(tab, f"Verification code not found for {account_email} within timeout.")
        except Exception as e:
            # Catch potential IMAP connection errors or other issues
            self.teardown(tab, f"Error accessing IMAP server or fetching email: {e}")


    def _verify_account_creation(self, tab: MixTab) -> bool:
        """Checks to see if we landed on the registration completed page."""
        return tab.wait.title_change("Registration completed")

    def _load_accounts(self) -> dict:
        """Loads accounts from file."""
        accounts = {}
        if (
            os.path.isfile(self.accounts_file)
            and os.path.getsize(self.accounts_file) > 0
        ):
            with open(self.accounts_file, "r") as f:
                accounts = json.load(f)
        return accounts

    def _save_accounts(self, accounts: dict) -> None:
        """Saves accounts dictionary to file."""
        with open(self.accounts_file, "w") as f:
            json.dump(accounts, f, indent=4)

    def _save_account_to_file(self, registration_info: dict) -> None:
        """Saves created account to accounts file."""
        logger.info(
            f"Saving registration info: {registration_info} to file: {self.accounts_file}"
        )
        accounts = self._load_accounts()
        accounts[registration_info["email"]] = registration_info
        self._save_accounts(accounts)

    # Refactored register_account with try...finally and status return
    def register_account(self) -> tuple[bool, str, dict | None]:
        """
        Wrapper function to fully register a Jagex account.
        Returns:
            tuple[bool, str, dict | None]: (success_status, message, registration_info or None)
        """
        registration_info = {
            "email": None, "password": self.password,
            "birthday": {"day": None, "month": None, "year": None},
            "proxy": {"enabled": self.use_proxies, "real_ip": None, "host": None, "port": None, "username": None, "password": None},
            "2fa": {"enabled": self.set_2fa, "setup_key": None, "backup_codes": None},
            "status": "pending", "message": ""
        }
        run_number = random.randint(10_000, 65_535)
        run_path = SCRIPT_DIR / f"run_{run_number}"
        browser = None
        tab = None
        filter_proxy = None
        proxy_extension_path = None

        try:
            os.makedirs(run_path, exist_ok=True) # Use exist_ok=True

            # --- Proxy Setup ---
            if self.use_proxies:
                proxy_extension_dir = run_path / "proxy_extension"
                proxy = self.get_next_proxy()
                logger.info(f"Using proxy: {proxy} for run {run_number}")
                proxy_parts = proxy.split(":")
                if len(proxy_parts) not in [2, 4]:
                    raise RegistrationError(f"Invalid proxy format: {proxy}")

                proxy_host, proxy_port = proxy_parts[0], proxy_parts[1]
                registration_info["proxy"].update({"host": proxy_host, "port": proxy_port})
                if len(proxy_parts) == 4:
                    proxy_username, proxy_password = proxy_parts[2], proxy_parts[3]
                    registration_info["proxy"].update({"username": proxy_username, "password": proxy_password})

                filter_proxy = TrafficFilterProxy(
                    allowed_url_patterns=["jagex", "cloudflare", "ipify"],
                    upstream_proxy=registration_info["proxy"],
                )
                filter_proxy.start_daemon()
                logger.info(f"Traffic filter proxy started on {filter_proxy.ip}:{filter_proxy.port}")

                proxy_extension_path = create_proxy_extension(
                    proxy_host=filter_proxy.ip, proxy_port=filter_proxy.port,
                    plugin_path=proxy_extension_dir,
                )
            # --- End Proxy Setup ---

            # --- Browser Setup ---
            logger.info("Setting up browser...")
            browser = self.get_new_browser(run_path, proxy_extension_path)
            tab = browser.latest_tab
            tab.set.auto_handle_alert()
            # tab.set.blocked_urls = self.urls_to_block # Consider if still needed with filter proxy
            tab.run_cdp("Network.enable")
            tab.run_cdp("Network.setBlockedURLs", urls=self.urls_to_block)
            logger.info("Browser setup complete.")
            time.sleep(2) # Allow extensions/proxy to load
            # --- End Browser Setup ---

            # --- Initial Navigation & Checks ---
            browser_ip = self.get_browser_ip(tab) # Can raise RegistrationError via teardown
            logger.info(f"Browser IP: {browser_ip}")
            registration_info["proxy"]["real_ip"] = browser_ip

            logger.info(f"Navigating to registration URL: {self.registration_url}")
            if not tab.get(self.registration_url):
                self.teardown(tab, f"Failed to navigate to URL: {self.registration_url}") # Raises RegistrationError

            # Wait for title explicitly after navigation
            if not tab.wait.title_change("Create a Jagex account", timeout=15):
                 # Check for block page before teardown
                if "Sorry, you have been blocked" in tab.html:
                     self.teardown(tab, "IP is blocked by Cloudflare.")
                self.teardown(tab, "Failed to load registration page (title mismatch or timeout).")

            # Check for challenge *after* page load attempt
            if self.check_for_challenge(tab):
                logger.info("Cloudflare challenge detected. Attempting bypass...")
                if not self.bypass_challenge(tab):
                    self.teardown(tab, "Failed to bypass Cloudflare challenge.")
                logger.info("Cloudflare challenge likely bypassed.")
                # Re-verify title after potential bypass navigation
                if not tab.wait.title_change("Create a Jagex account", timeout=15):
                     self.teardown(tab, "Failed to reach registration page after CF bypass.")

            # self.click_element(tab, "#CybotCookiebotDialogBodyButtonDecline", False) # Optional cookie decline
            # --- End Initial Navigation & Checks ---

            # --- Registration Form ---
            username = self.generate_username()
            domain = self.get_account_domain()
            registration_info["email"] = f"{username}@{domain}"
            logger.info(f"Generated email: {registration_info['email']}")

            registration_info["birthday"]["day"] = random.randint(1, 25)
            registration_info["birthday"]["month"] = random.randint(1, 12)
            registration_info["birthday"]["year"] = random.randint(1979, 2010) # Ensure age is valid
            bday_str = f"{registration_info['birthday']['day']}/{registration_info['birthday']['month']}/{registration_info['birthday']['year']}"
            logger.info(f"Generated birthday: {bday_str}")

            self.click_and_type(tab, "@id:email", registration_info["email"])
            self.click_and_type(tab, "@id:registration-start-form--field-day", str(registration_info["birthday"]["day"]))
            self.click_and_type(tab, "@id:registration-start-form--field-month", str(registration_info["birthday"]["month"]))
            self.click_and_type(tab, "@id:registration-start-form--field-year", str(registration_info["birthday"]["year"]))
            self.click_element(tab, "@id:registration-start-accept-agreements")
            self.click_element(tab, "@id:registration-start-form--continue-button")
            tab.wait.doc_loaded() # Wait for next step page
            logger.info("Filled initial registration form.")
            # --- End Registration Form ---

            # --- Email Verification ---
            code = self._get_verification_code(tab, registration_info["email"]) # Can raise RegistrationError
            self.click_and_type(tab, "@id:registration-verify-form-code-input", code)
            self.click_element(tab, "@id:registration-verify-form-continue-button")
            tab.wait.doc_loaded()
            logger.info("Email verification submitted.")
            # --- End Email Verification ---

            # --- Account Name & Password ---
            self.click_and_type(tab, "@id:displayName", username) # Use generated username
            self.click_element(tab, "@id:registration-account-name-form--continue-button")
            tab.wait.doc_loaded()

            self.click_and_type(tab, "@id:password", self.password)
            self.click_and_type(tab, "@id:repassword", self.password)
            self.click_element(tab, "@id:registration-password-form--create-account-button")
            tab.wait.doc_loaded()
            logger.info("Account name and password submitted.")
            # --- End Account Name & Password ---

            # --- Verify Creation & Optional 2FA ---
            if not self._verify_account_creation(tab):
                self.teardown(tab, "Failed to verify account creation (final page title mismatch).")
            logger.info("Account creation verified.")

            if self.set_2fa:
                logger.info("Setting up 2FA...")
                if not tab.get(self.management_url):
                    self.teardown(tab, "Failed to navigate to account management page for 2FA.")
                tab.wait.url_change(self.management_url)
                tab.wait.doc_loaded()

                self.click_element(tab, "@data-testid:mfa-enable-totp-button")
                tab.wait.doc_loaded() # Wait for 2FA setup section

                self.click_element(tab, "@id:authentication-setup-show-secret")

                setup_key_element = self.find_element(tab, "@id:authentication-setup-secret-key")
                if not setup_key_element or not setup_key_element.text:
                     self.teardown(tab, "Could not find or read 2FA setup key element.")
                registration_info["2fa"]["setup_key"] = setup_key_element.text.strip() # Add strip()
                logger.debug(f"Extracted 2FA setup key: {registration_info['2fa']['setup_key']}")

                # It might be safer to click the button *before* generating the TOTP
                self.click_element(tab, "@data-testid:authenticator-setup-qr-button") # Continue button

                totp_code = pyotp.TOTP(registration_info["2fa"]["setup_key"]).now()
                logger.debug(f"Generated TOTP code: {totp_code}")

                self.click_and_type(tab, "@id:authentication-setup-verification-code", totp_code)
                self.click_element(tab, "@data-testid:authentication-setup-qr-code-submit-button")
                tab.wait.doc_loaded() # Wait for backup codes page

                backup_codes_element = self.find_element(tab, "@id:authentication-setup-complete-codes")
                if not backup_codes_element or not backup_codes_element.text:
                     self.teardown(tab, "Could not find or read 2FA backup codes element.")
                # Split codes and filter empty lines
                backup_codes = [code.strip() for code in backup_codes_element.text.split('\n') if code.strip()]
                registration_info["2fa"]["backup_codes"] = backup_codes
                logger.info(f"Successfully set up 2FA. Got {len(backup_codes)} backup codes.")
            # --- End Verify Creation & Optional 2FA ---

            # --- Success ---
            registration_info["status"] = "success"
            registration_info["message"] = "Account registered successfully."
            self._save_account_to_file(registration_info)
            logger.info(f"Successfully registered and saved account: {registration_info['email']}")
            return True, registration_info["message"], registration_info
            # --- End Success ---

        except RegistrationError as e:
            # Logged in teardown, just return failure status
            registration_info["status"] = "failed"
            registration_info["message"] = str(e)
            return False, str(e), registration_info
        except Exception as e:
            # Catch unexpected errors
            logger.exception(f"An unexpected error occurred during registration for run {run_number}: {e}")
            # Try to teardown gracefully if tab exists
            if tab:
                try:
                    tab.close()
                except: pass # Ignore errors during cleanup teardown
            registration_info["status"] = "failed"
            registration_info["message"] = f"Unexpected error: {e}"
            return False, registration_info["message"], registration_info
        finally:
            # --- Cleanup ---
            logger.debug(f"Starting cleanup for run {run_number}")
            if browser:
                try:
                    logger.debug("Closing browser...")
                    browser.quit() # Use quit() for the whole browser
                except Exception as e:
                    logger.warning(f"Error closing browser: {e}")

            # Cache update logic (keep as is for now, but consider GUI control later)
            run_cache_path = run_path / "cache"
            if os.path.isdir(run_cache_path) and os.path.isdir(self.cache_folder):
                 try:
                    run_cache_size = self.get_dir_size(run_cache_path)
                    original_cache_size = self.get_dir_size(self.cache_folder)
                    if original_cache_size == 0:
                        size_diff_percent = 100 if run_cache_size > 0 else 0
                    else:
                        size_diff_percent = (abs(run_cache_size - original_cache_size) / original_cache_size * 100)

                    logger.debug(f"Run cache size: {run_cache_size}, Original cache size: {original_cache_size}, Diff: {size_diff_percent:.2f}%")
                    if size_diff_percent >= self.cache_update_threshold:
                        with self.cache_folder_lock:
                            logger.info(f"Updating main cache from run {run_number} cache (diff >= {self.cache_update_threshold}%).")
                            shutil.rmtree(self.cache_folder)
                            shutil.copytree(run_cache_path, self.cache_folder)
                 except Exception as e:
                     logger.warning(f"Error updating cache: {e}")
            elif os.path.isdir(run_cache_path) and not os.path.isdir(self.cache_folder):
                 try:
                    logger.info("Main cache doesn't exist. Copying run cache to main cache.")
                    shutil.copytree(run_cache_path, self.cache_folder)
                 except Exception as e:
                     logger.warning(f"Error copying initial cache: {e}")


            if os.path.exists(run_path):
                try:
                    logger.debug(f"Deleting run temp folder: {run_path}")
                    shutil.rmtree(run_path)
                except Exception as e:
                    logger.warning(f"Error deleting run folder {run_path}: {e}")

            if filter_proxy:
                try:
                    logger.debug("Stopping traffic filter proxy server.")
                    filter_proxy.stop()
                except Exception as e:
                    logger.warning(f"Error stopping filter proxy: {e}")
            logger.debug(f"Cleanup finished for run {run_number}")
            # --- End Cleanup ---

# Keep main function for standalone execution, but GUI will bypass this
def main():
    # Basic logging setup if run standalone
    logger.add("account_creator.log", rotation="10 MB", level="DEBUG")
    logger.info("Starting Account Creator (standalone mode)...")

    try:
        ac = AccountCreator()
    except Exception as e:
        logger.exception(f"Failed to initialize AccountCreator: {e}")
        sys.exit(f"Initialization Error: {e}")

    threads = []
    for i in range(ac.threads):
        logger.info(f"Starting thread {i+1}/{ac.threads}")
        thread = threading.Thread(target=ac.register_account, daemon=True) # Use daemon threads
        threads.append(thread)
        thread.start()
        time.sleep(1) # Stagger start

    # Wait for threads to complete (optional, maybe add timeout)
    for thread in threads:
        thread.join()

    logger.info("All threads finished.")

if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
from pathlib import Path

# Try importing AccountCreator, handle potential import errors
try:
    from main import AccountCreator, RegistrationError, SCRIPT_DIR
    from loguru import logger # Use the same logger instance if configured
except ImportError as e:
    messagebox.showerror("Import Error", f"Failed to import necessary components from main.py: {e}\n\nPlease ensure main.py is in the same directory.")
    exit()
except Exception as e:
    messagebox.showerror("Error", f"An unexpected error occurred during import: {e}")
    exit()

# --- GUI Application Class ---
class AccountCreatorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Jagex Account Creator")
        self.geometry("600x450") # Adjusted size

        # Configure logger (optional, main.py might already configure it)
        log_file = SCRIPT_DIR / "gui_account_creator.log"
        try:
            logger.add(log_file, rotation="10 MB", level="INFO")
        except Exception as e:
            print(f"Warning: Could not configure file logging for GUI: {e}") # Non-critical

        self.account_creator_instance = None
        self.worker_threads = []
        self.result_queue = queue.Queue()
        self.threads_started = 0
        self.threads_completed = 0
        self.is_running = False

        # --- Style ---
        self.style = ttk.Style(self)
        self.style.theme_use('clam') # Or 'vista', 'xpnative' etc. depending on OS

        # --- Main Frame ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Configuration Info (Read-only) ---
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        try:
            # Create a temporary instance just to read config for display
            temp_ac = AccountCreator()
            self.config_info = {
                "Threads (from config)": temp_ac.threads,
                "Headless": temp_ac.headless,
                "Proxies Enabled": temp_ac.use_proxies,
                "Set 2FA": temp_ac.set_2fa,
                "Domains": ", ".join(temp_ac.domains),
                "Accounts File": temp_ac.accounts_file.name,
            }
            del temp_ac # Clean up temporary instance
        except Exception as e:
            self.config_info = {"Error": f"Could not load config: {e}"}
            logger.error(f"Failed to load config for GUI display: {e}")

        for i, (key, value) in enumerate(self.config_info.items()):
             ttk.Label(config_frame, text=f"{key}:").grid(row=i, column=0, sticky=tk.W, padx=5)
             ttk.Label(config_frame, text=str(value)).grid(row=i, column=1, sticky=tk.W, padx=5)


        # --- Controls Frame ---
        controls_frame = ttk.Frame(main_frame, padding="5")
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Number of Accounts:").pack(side=tk.LEFT, padx=5)
        self.num_accounts_var = tk.StringVar(value="1") # Default to 1
        self.num_accounts_entry = ttk.Entry(controls_frame, textvariable=self.num_accounts_var, width=5)
        self.num_accounts_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(controls_frame, text="Start Creation", command=self.start_creation)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = ttk.Button(controls_frame, text="Stop (Not Implemented)", state=tk.DISABLED) # Placeholder
        self.stop_button.pack(side=tk.LEFT, padx=5)


        # --- Status/Log Area ---
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.status_text = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=15, state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True)

        # --- Progress Bar ---
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(5, 10))


        # Start checking the queue
        self.check_queue()

    def log_status(self, message, level="INFO"):
        """Appends a message to the status text area."""
        self.status_text.config(state=tk.NORMAL)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp} - {level}] {message}\n")
        self.status_text.see(tk.END) # Scroll to the end
        self.status_text.config(state=tk.DISABLED)
        # Also log to file via loguru
        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        else:
            logger.info(message)


    def start_creation(self):
        """Starts the account creation process in separate threads."""
        if self.is_running:
            messagebox.showwarning("Already Running", "Account creation is already in progress.")
            return

        try:
            num_to_create = int(self.num_accounts_var.get())
            if num_to_create <= 0:
                raise ValueError("Number of accounts must be positive.")
        except ValueError as e:
            messagebox.showerror("Invalid Input", f"Please enter a valid positive number for accounts: {e}")
            return

        # --- Initialize Account Creator ---
        # Do this here to ensure config is fresh if changed between runs
        try:
            self.account_creator_instance = AccountCreator()
            # Re-check config consistency if needed, or update display
        except Exception as e:
             messagebox.showerror("Initialization Error", f"Failed to initialize AccountCreator: {e}")
             logger.exception("Failed to initialize AccountCreator in start_creation")
             return
        # --- End Initialization ---

        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        # self.stop_button.config(state=tk.NORMAL) # Enable stop when implemented
        self.progress_var.set(0)
        self.threads_started = num_to_create
        self.threads_completed = 0
        self.worker_threads = [] # Clear previous threads

        self.log_status(f"Starting creation process for {num_to_create} account(s)...")

        for i in range(num_to_create):
            thread = threading.Thread(target=self.run_registration_worker, args=(i+1,), daemon=True)
            self.worker_threads.append(thread)
            thread.start()
            self.log_status(f"Worker thread {i+1} started.")
            time.sleep(0.1) # Small delay between thread starts

    def run_registration_worker(self, worker_id):
        """The function executed by each worker thread."""
        self.log_status(f"Worker {worker_id}: Starting registration.")
        result_data = {"success": False, "message": "Worker started", "info": None, "worker_id": worker_id}
        try:
            # Use the shared instance (ensure thread-safety within AccountCreator if needed, locks seem present)
            if not self.account_creator_instance:
                 raise RuntimeError("AccountCreator instance not initialized.")

            success, message, reg_info = self.account_creator_instance.register_account()
            result_data["success"] = success
            result_data["message"] = message
            result_data["info"] = reg_info # Contains email etc.
            level = "INFO" if success else "ERROR"
            self.log_status(f"Worker {worker_id}: {'Success' if success else 'Failed'} - {message}", level=level)

        except RegistrationError as e:
            result_data["message"] = f"Worker {worker_id}: Registration Error - {e}"
            self.log_status(result_data["message"], level="ERROR")
        except Exception as e:
            result_data["message"] = f"Worker {worker_id}: Unexpected Error - {e}"
            self.log_status(result_data["message"], level="ERROR")
            logger.exception(f"Unexpected error in worker thread {worker_id}") # Log full traceback
        finally:
            self.result_queue.put(result_data)


    def check_queue(self):
        """Periodically checks the queue for results from worker threads."""
        try:
            while True: # Process all available messages in the queue
                result = self.result_queue.get_nowait()
                self.threads_completed += 1

                # Update GUI based on result
                email = result.get("info", {}).get("email", "N/A") if result.get("info") else "N/A"
                status_msg = f"Account {email}: {'SUCCESS' if result['success'] else 'FAILED'}. Reason: {result['message']}"
                # self.log_status(status_msg, level="INFO" if result['success'] else "ERROR") # Already logged in worker

                # Update progress bar
                progress = (self.threads_completed / self.threads_started) * 100 if self.threads_started > 0 else 0
                self.progress_var.set(progress)

                if self.threads_completed >= self.threads_started:
                    self.log_status(f"All {self.threads_started} creation tasks finished.")
                    self.is_running = False
                    self.start_button.config(state=tk.NORMAL)
                    # self.stop_button.config(state=tk.DISABLED)
                    self.progress_var.set(100) # Ensure it reaches 100%
                    break # Exit loop if all done for this check cycle

        except queue.Empty:
            pass # No messages in the queue, do nothing
        except Exception as e:
            self.log_status(f"Error checking queue: {e}", level="ERROR")
            logger.exception("Error in check_queue")


        # Schedule the next check
        self.after(200, self.check_queue) # Check every 200ms


# --- Main Execution ---
if __name__ == "__main__":
    # Ensure essential files/dirs exist before starting GUI
    try:
        if not (SCRIPT_DIR / "config.ini").is_file():
             messagebox.showerror("Missing File", "config.ini not found. Please create it.")
             exit()
        proxies_dir = SCRIPT_DIR / "proxies"
        proxies_file = proxies_dir / "proxies.txt"
        proxies_dir.mkdir(exist_ok=True) # Create proxies dir if needed
        # Create empty proxies.txt if it doesn't exist and proxies are enabled in config (optional check)
        # config = configparser.ConfigParser()
        # config.read(SCRIPT_DIR / "config.ini")
        # if config.getboolean("proxies", "enabled", fallback=False) and not proxies_file.is_file():
        #      proxies_file.touch()
        #      print("Created empty proxies.txt as proxies are enabled but file was missing.")

    except Exception as e:
         messagebox.showerror("Startup Error", f"Error during pre-run check: {e}")
         exit()

    app = AccountCreatorGUI()
    app.mainloop()

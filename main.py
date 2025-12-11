import random
import string
import csv
import os
import hashlib
import base64
import re
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from typing import List, Tuple, Dict, Union
import requests 
import webbrowser 
import time
from datetime import date, timedelta 
from datetime import datetime 
    

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    
    def Fernet_Fallback(*args, **kwargs):
        messagebox.showerror("Dependency Error", 
                             "The 'cryptography' library is missing. Please run 'pip install cryptography' to enable encryption features.")
        return None
    Fernet = None
    InvalidToken = Exception 
else:
    Fernet_Fallback = Fernet



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


SALT_FILE = os.path.join(DATA_DIR, "salt.key")
DB_FILE = os.path.join(DATA_DIR, "password_vault.txt")
CSV_FILE = os.path.join(DATA_DIR, "passwords_export.csv") 
TOP_PASSWORDS_FILE = os.path.join(DATA_DIR, "top10k.txt")


UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS


WORD_LIST = [
    "sunshine", "mountain", "keyboard", "elephant", "whisper", "ocean",
    "dragon", "puzzle", "bicycle", "galaxy", "banana", "castle",
    "coffee", "forest", "hammer", "jacket", "limousine", "mystery",
    "octopus", "pirate", "quilt", "robot", "shadow", "tornado",
    "umbrella", "volcano", "waffle", "xylophone", "yacht", "zeppelin",
    "lightning", "treasure", "diamond", "rocket", "penguin", "walrus"
]


passwords: List[Dict[str, str]] = []
cipher_suite: Union[Fernet, None] = None
master_password_set = False


TOP_PASSWORDS = set()


PRIMARY_COLOR = "#1c1c1c" 
SECONDARY_COLOR = "#333333" 
TEXT_COLOR = "white"
INPUT_TEXT_COLOR = "#000000" 
FONT_FAMILY = "Arial"
HEADER_FONT = (FONT_FAMILY, 14, "bold")
NORMAL_FONT = (FONT_FAMILY, 10)
BUTTON_FONT = (FONT_FAMILY, 10, "bold")
ERROR_COLOR = "#F44336" 


PASSWORD_HELP_URL = "https://www.waldenu.edu/programs/information-technology/resource/cybersecurity-101-why-choosing-a-secure-password-in-so-important"


# ====================================================================
# 1. SECURE KEY MANAGEMENT (Master Password & Salt/Peppering)
# ====================================================================

def derive_key_from_password(master_password: str) -> Union[Fernet, None]:
    """
    Uses the Master Password and a unique Salt to securely derive the Fernet key.
    Ensures salt integrity during creation and loading.
    """
    if not Fernet:
        return None
    
   
    os.makedirs(DATA_DIR, exist_ok=True)
    
    salt = None
    
   
    if os.path.exists(SALT_FILE):
        try:
            with open(SALT_FILE, "rb") as f:
                salt = f.read()
            
            if salt and len(salt) != 16:
                 messagebox.showerror("Security Error", "Corrupted security salt detected. The vault cannot be unlocked. Please delete 'data/salt.key' to reset the Master Password.")
                 return None
        except Exception as e:
            messagebox.showerror("Security Error", f"Could not load salt file: {e}")
            return None
    
    
    if not salt:
        salt = os.urandom(16)
        try:
            
            with open(SALT_FILE, "wb") as f:
                f.write(salt)
        except Exception as e:
            messagebox.showerror("Security Error", f"Could not save new salt file. Check permissions: {e}")
            return None

    
    key_material = master_password.encode() + salt
    
    for _ in range(100000): 
        key_material = hashlib.sha256(key_material).digest()
    
    fernet_key = base64.urlsafe_b64encode(key_material[:32])
    
    return Fernet(fernet_key)

def encrypt_data(data: str) -> str:
    
    if cipher_suite:
        return cipher_suite.encrypt(data.encode()).decode()
    return data

def decrypt_data(data: str) -> str:
    
    if cipher_suite:
        try:
            
            return cipher_suite.decrypt(data.encode()).decode()
        except InvalidToken:
            return "[DECRYPTION FAILED - Check Master Password]" 
        except Exception:
            return "[DECRYPTION FAILED - Data Corrupt]"
    return data


# ====================================================================
# 2. PASSWORD MANAGER CORE FUNCTIONS
# ====================================================================

def _process_encrypted_csv(filepath: str, append_to_vault: bool) -> bool:
    """
    Helper function to read and process the J.A.R.V.I.S. encrypted CSV format.
    Assumes the file is encrypted with the current Master Password.
    Returns True on success, False on decryption failure.
    
    UPDATED: Now handles 4 or 5 columns for backward compatibility.
    """
    global passwords
    loaded_passwords = []
    
    if not os.path.exists(filepath):
        if not append_to_vault: 
            return False 
        return True

    try:
        with open(filepath, 'r') as f:
            reader = csv.reader(f)
            
            
            
            line_number = 0
            for row in reader:
                line_number += 1
                
                
                if len(row) < 4 or len(row) > 5:
                    messagebox.showwarning("Vault Integrity Warning", f"Skipping line {line_number} in file. Expected 4 or 5 columns, found {len(row)}. Vault structure is inconsistent.")
                    continue

                encrypted_name, encrypted_url, encrypted_username, encrypted_password = row[0], row[1], row[2], row[3]
                
                
                created_at = row[4] if len(row) == 5 else "2020-01-01" 
                
                
                decrypted_name = decrypt_data(encrypted_name) 
                
                
                if "[DECRYPTION FAILED" in decrypted_name:
                     
                     return False 
                     
                
                entry = {
                    "name": decrypted_name,
                    "url": decrypt_data(encrypted_url),
                    "username": decrypt_data(encrypted_username),
                    "password_encrypted": encrypted_password, 
                    "created_at": created_at 
                }
                loaded_passwords.append(entry)
                
        if not append_to_vault:
            passwords.clear()
        
        passwords.extend(loaded_passwords)
        return True
        
    except Exception as e:
        
        print(f"Encrypted processing failed with unexpected error: {e}")
        return False

def _process_plaintext_csv(filepath: str) -> int:
   
    global passwords
    imported_count = 0
    current_date_str = date.today().strftime("%Y-%m-%d") 
    
    if not os.path.exists(filepath):
        return 0

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            
            
            try:
                next(reader) 
            except StopIteration:
                return 0 

            line_number = 1
            for row in reader:
                line_number += 1
                
                
                if len(row) < 4:
                    messagebox.showwarning("Plaintext Import Warning", f"Skipping line {line_number} in file. Expected at least 4 columns (Name, URL, Username, Password), found {len(row)}.")
                    continue

                name, url, username, password_raw = row[0], row[1], row[2], row[3]
                
                
                encrypted_password = encrypt_data(password_raw)
                
                entry = {
                    "name": name.strip(),
                    "url": url.strip(),
                    "username": username.strip(),
                    "password_encrypted": encrypted_password,
                    "created_at": current_date_str 
                }
                passwords.append(entry)
                imported_count += 1
                
        return imported_count
        
    except Exception as e:
        messagebox.showerror("Plaintext Import Error", f"Failed to process plaintext CSV: {e}")
        return -1

def load_passwords_from_vault() -> bool:
    
    global passwords
    
    if not os.path.exists(DB_FILE):
        passwords.clear()
        return True
        
    success = _process_encrypted_csv(DB_FILE, False)
    if not success:
        passwords.clear()
    return success


def save_passwords_to_vault():
    
    if not master_password_set:
        return 
        
    try:
       
        os.makedirs(DATA_DIR, exist_ok=True)
        
        with open(DB_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            for entry in passwords:
                
                encrypted_row = [
                    encrypt_data(entry['name']),
                    encrypt_data(entry['url']),
                    encrypt_data(entry['username']),
                    entry['password_encrypted'],
                    
                    entry.get('created_at', date.today().strftime("%Y-%m-%d")) 
                ]
                writer.writerow(encrypted_row)
    except Exception as e:
        messagebox.showerror("Vault Error", f"Failed to save vault data: {e}")


# ====================================================================
# 3. GENERATION & VALIDATION LOGIC
# ====================================================================

def _load_top_passwords():
    """Loads the external list of top passwords."""
    global TOP_PASSWORDS
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(TOP_PASSWORDS_FILE):
        try:
            with open(TOP_PASSWORDS_FILE, 'r', encoding='utf-8') as f:
                
                TOP_PASSWORDS = {line.strip().lower() for line in f if line.strip()}
            print(f"Loaded {len(TOP_PASSWORDS)} common passwords from {TOP_PASSWORDS_FILE}.")
        except Exception as e:
            print(f"Warning: Could not load top passwords file: {e}")
            messagebox.showwarning("Security Warning", f"Could not load top passwords list. Check file encoding or permissions for '{TOP_PASSWORDS_FILE}'.")
    else:
        print(f"Warning: Top passwords file not found at {TOP_PASSWORDS_FILE}.")
        messagebox.showwarning("Security Warning", f"Top passwords list file not found. Create the 'data' folder and place '{os.path.basename(TOP_PASSWORDS_FILE)}' inside it.")



def check_for_pwned_status(password: str) -> Tuple[bool, int]:
   
    if not password:
        return False, 0
    
    
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    HIBP_API_URL = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        
        response = requests.get(HIBP_API_URL, timeout=5)
        response.raise_for_status() 
        
        
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                
                if ":" in line:
                    pwned_suffix, count_str = line.split(":", 1)
                    if pwned_suffix == suffix:
                        return True, int(count_str)
        
        return False, 0

    except requests.exceptions.RequestException as e:
        print(f"HIBP API Error: {e}")
        
        return False, -1 


def generate_passphrase(num_words: int = 3, separator: str = '-', user_word: str = '') -> str:
    
    
    words_to_select = num_words - (1 if user_word else 0)
    words_to_select = max(2, words_to_select) 

    selected_words = random.sample(WORD_LIST, words_to_select)
    
    if user_word:
        selected_words.append(re.sub(r'[\s{}]'.format(re.escape(separator)), '', user_word))
        random.shuffle(selected_words) 

    num_digits = random.randint(1, 2)
    num_specials = random.randint(1, 2)
    
    embellishments = []
    embellishments.append("".join(random.choices(DIGITS, k=num_digits)))
    embellishments.append("".join(random.choices(SPECIAL_CHARS, k=num_specials)))
    
    all_elements = selected_words + embellishments
    random.shuffle(all_elements)

    passphrase = separator.join([str(e) for e in all_elements])
    return passphrase.capitalize()


def generate_password(length: int) -> Union[str, None]:
    
    if length < 4:
        return None

    password_list = [
        random.choice(UPPERCASE),
        random.choice(LOWERCASE),
        random.choice(DIGITS),
        random.choice(SPECIAL_CHARS)
    ]

    remaining_length = length - 4
    for _ in range(remaining_length):
        password_list.append(random.choice(ALL_CHARS))

    random.shuffle(password_list)
    return "".join(password_list)

def check_password_strength(password: str) -> Tuple[str, str]:
   
    score = 0
    feedback = ""
    length = len(password)
    
    
    if password.lower() in TOP_PASSWORDS:
        strength = "WEAK"
        feedback = "• DANGER: This is a top common password (Found in 10,000 list). You must not use it.\n"
        return strength, feedback
    
   
    count_upper = sum(1 for c in password if c in UPPERCASE)
    count_lower = sum(1 for c in password if c in LOWERCASE)
    count_digit = sum(1 for c in password if c in DIGITS)
    count_special = sum(1 for c in password if c in SPECIAL_CHARS)

    
    if length >= 20: 
        score += 8
    elif length >= 16:
        score += 6
    elif length >= 12:
        score += 4
    elif length >= 8:
        score += 2
    
    if length < 8:
        feedback += "• WEAK: Length is less than the recommended minimum (8).\n"

    
    char_types = 0
    if count_upper > 0: char_types += 1
    if count_lower > 0: char_types += 1
    if count_digit > 0: char_types += 1
    if count_special > 0: char_types += 1

    
    if char_types == 4:
        score += 5
        feedback += "• Diversity: Uses all 4 character types (Max Bonus).\n"
    elif char_types == 3:
        score += 3
        feedback += "• Diversity: Uses 3 character types.\n"
    elif char_types == 2:
        score += 1
        feedback += "• Diversity: Uses 2 character types.\n"

   
    digit_bonus = min(2, count_digit // 2) 
    score += digit_bonus
    if count_digit == 0:
        feedback += "• Missing digits.\n"
    
    
    special_bonus = min(3, count_special) 
    score += special_bonus
    if count_special == 0:
        feedback += "• Missing special characters.\n"

    
    if count_upper == 0:
        feedback += "• Missing uppercase letters.\n"
    if count_lower == 0:
        feedback += "• Missing lowercase letters.\n"

    

    if score >= 16: strength = "EXCEPTIONAL"
    elif score >= 12: strength = "VERY STRONG"
    elif score >= 8: strength = "STRONG"
    elif score >= 4: strength = "MEDIUM"
    else: strength = "WEAK"
    
    return strength, feedback


# ====================================================================
# 4. GUI CLASS AND IMPLEMENTATION
# ====================================================================

class JarvisTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JARVIS")
        self.geometry("600x480")
        
        self.configure(bg=SECONDARY_COLOR) 
        
        
        _load_top_passwords()
        
        
        self.password_visible = False 
        
        
        self.checked_items = {} 

        
        VIEW_ICON_PATH = os.path.join(BASE_DIR, "GUI", "View(1).png")
        HIDE_ICON_PATH = os.path.join(BASE_DIR, "GUI", "Hide(1).png")

        
        try:
            
            self.view_icon = tk.PhotoImage(file=VIEW_ICON_PATH)
            self.hide_icon = tk.PhotoImage(file=HIDE_ICON_PATH)
            
            
            self.view_icon_small = self.view_icon.subsample(30, 30)
            self.hide_icon_small = self.hide_icon.subsample(30, 30)
            
        except tk.TclError:
            
            self.view_icon_small = None
            self.hide_icon_small = None
            print("Warning: Could not load View(1).png or Hide(1).png. Using text button.")
        
        
        style = ttk.Style(self)
        
        
        style.theme_create("jarvis_style", parent="alt", settings={
            
            "TNotebook": {"configure": {"background": PRIMARY_COLOR}},
            "TNotebook.Tab": {"configure": {"padding": [10, 5], "background": SECONDARY_COLOR, "foreground": TEXT_COLOR},
                               "map": {"background": [("selected", PRIMARY_COLOR)], "foreground": [("selected", TEXT_COLOR)]}},
            "TLabel": {"configure": {"background": PRIMARY_COLOR, "foreground": TEXT_COLOR, "font": NORMAL_FONT}},
            
            
            "TButton": {"configure": {"background": SECONDARY_COLOR, 
                                      "foreground": TEXT_COLOR, 
                                      "font": BUTTON_FONT, 
                                      "relief": "flat", # Default state is flat
                                      "borderwidth": 1, # Minimal border
                                      "padding": 5,
                                      "fieldbackground": SECONDARY_COLOR,
                                      "bordercolor": SECONDARY_COLOR,
                                      "focusthickness": 0,
                                      "cursor": "hand2"}, # NEW: Hand pointer cursor
                        "map": {"background": [("active", PRIMARY_COLOR)], # Darken on hover
                                "relief": [("active", "flat")], # Force 'flat' relief even when active/clicked
                                "foreground": [("active", TEXT_COLOR)]}},
            
            "Treeview": {"configure": {"background": SECONDARY_COLOR, "foreground": TEXT_COLOR, "fieldbackground": SECONDARY_COLOR}},
            "Treeview.Heading": {"configure": {"background": PRIMARY_COLOR, "foreground": TEXT_COLOR}}
        })
        
        style.theme_use("jarvis_style")
        
        
        self.check_box_empty = tk.PhotoImage(width=16, height=16)
        
        self.check_box_empty.put("white", to=(0, 0, 15, 15)) 
        
        self.check_box_empty.put(SECONDARY_COLOR, to=(0, 0, 1, 15)) 
        self.check_box_empty.put(SECONDARY_COLOR, to=(14, 0, 15, 15)) 
        self.check_box_empty.put(SECONDARY_COLOR, to=(0, 0, 15, 1)) 
        self.check_box_empty.put(SECONDARY_COLOR, to=(0, 14, 15, 15)) 
        self.check_box_empty.put(PRIMARY_COLOR, to=(2, 2, 13, 13)) 
        
        
        self.check_box_checked = tk.PhotoImage(width=16, height=16)
        
        self.check_box_checked.put("#4CAF50", to=(0, 0, 15, 15))
        
        
        dot_color = "white"
        
        self.check_box_checked.put(dot_color, to=(5, 5, 10, 10))


        
        self.notebook = ttk.Notebook(self)
        
        self.lock_frame = tk.Frame(self, bg=PRIMARY_COLOR)
        self.lock_frame.pack(expand=True, fill="both")
        self.setup_lock_screen()
        
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    

    def setup_lock_screen(self):
        
        self.lock_frame.config(bg=PRIMARY_COLOR)
        
        title = ttk.Label(self.lock_frame, text="🔒 FRIDAY VAULT ACCESS 🔒", font=HEADER_FONT)
        title.pack(pady=(40, 20))

        ttk.Label(self.lock_frame, text="Master Password:", font=NORMAL_FONT).pack(pady=5)
        
        
        entry_frame = tk.Frame(self.lock_frame, bg=PRIMARY_COLOR)
        entry_frame.pack(pady=5)
        
        
        self.mp_entry = ttk.Entry(entry_frame, show="*", width=25, font=NORMAL_FONT, 
                                  background=SECONDARY_COLOR, foreground=INPUT_TEXT_COLOR)
        self.mp_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        
        initial_icon = self.hide_icon_small if self.hide_icon_small else None
        initial_text = "" if initial_icon else "Hide"

        self.mp_toggle_btn = ttk.Button(entry_frame, 
                                        image=initial_icon, 
                                        text=initial_text, 
                                        command=self.toggle_master_password_visibility,
                                        width=5 if not initial_icon else 0,
                                        compound=tk.LEFT)
        self.mp_toggle_btn.pack(side=tk.LEFT)
        
        
        self.mp_entry.bind('<Return>', lambda event: self.unlock_vault())

        ttk.Button(self.lock_frame, text="UNLOCK VAULT", command=self.unlock_vault).pack(pady=20)
        
        
        self.lock_status = ttk.Label(self.lock_frame, text="\n    Enter your Master Password to proceed.\n\n(If opened app for first time, set new password)", font=NORMAL_FONT)
        self.lock_status.pack(pady=10)

    def toggle_master_password_visibility(self):
        
        if self.mp_entry.cget('show') == '*':
            
            self.mp_entry.config(show="")
            
            if self.view_icon_small:
                self.mp_toggle_btn.config(image=self.view_icon_small, text="") 
            else:
                self.mp_toggle_btn.config(text="Show")
        else:
            
            self.mp_entry.config(show="*")
            
            if self.hide_icon_small:
                self.mp_toggle_btn.config(image=self.hide_icon_small, text="") 
            else:
                self.mp_toggle_btn.config(text="Hide")


    def unlock_vault(self):
        
        global cipher_suite, master_password_set
        
        master_password = self.mp_entry.get()
        if not master_password:
            self.lock_status.config(text="Password field cannot be empty.", foreground=ERROR_COLOR)
            return

       
        potential_cipher_suite = derive_key_from_password(master_password)
        
        if not potential_cipher_suite:
             
             self.lock_status.config(text="ERROR: Key derivation failed. Check error message.", foreground=ERROR_COLOR)
             return

        vault_exists = os.path.exists(DB_FILE)
        
        
        global cipher_suite
        cipher_suite = potential_cipher_suite 
        
        
        if vault_exists and not load_passwords_from_vault():
            messagebox.showerror("Authentication Failed", "❌ Incorrect Master Password. Access Denied.")
            cipher_suite = None # Discard the wrong key
            self.lock_status.config(text="❌ Invalid Master Password.", foreground=ERROR_COLOR)
            return
        
        
        master_password_set = True
        
        
        self.mp_entry.delete(0, tk.END) 
        
        self.lock_frame.pack_forget() 
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both") 
        self.setup_tabs()
        self.title("FRIDAY Secure Password Tool - VAULT ONLINE")


    def setup_tabs(self):
        
        
        
        self.gen_frame = tk.Frame(self.notebook, bg=PRIMARY_COLOR)
        self.notebook.add(self.gen_frame, text="🔑 Generator")
        self.setup_generator_tab(self.gen_frame)

        
        self.val_frame = tk.Frame(self.notebook, bg=PRIMARY_COLOR)
        self.notebook.add(self.val_frame, text="🔍 Validator")
        self.setup_validator_tab(self.val_frame)

        
        self.vault_frame = tk.Frame(self.notebook, bg=PRIMARY_COLOR)
        self.notebook.add(self.vault_frame, text="🔒 Vault Manager")
        self.setup_vault_tab(self.vault_frame)
        
   
    def open_password_education_link(self):
        """Opens the predefined external link in the user's default web browser."""
        try:
            webbrowser.open_new_tab(PASSWORD_HELP_URL)
        except Exception as e:
            messagebox.showerror("Web Browser Error", f"Failed to open link: {e}\nURL: {PASSWORD_HELP_URL}")

    def setup_generator_tab(self, parent):
        
        ttk.Label(parent, text="Generated Password:", font=HEADER_FONT).pack(pady=(15, 5))
        
        self.gen_output = ttk.Entry(parent, width=50, font=NORMAL_FONT, state='readonly', 
                                    background=SECONDARY_COLOR, foreground=INPUT_TEXT_COLOR)
        self.gen_output.pack(pady=5, padx=10)
        
        
        action_frame = tk.Frame(parent, bg=PRIMARY_COLOR)
        action_frame.pack(pady=5)

        
        ttk.Button(action_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=0, column=0, padx=5)
        
        
        self.save_gen_btn = ttk.Button(action_frame, text="Save to Vault", command=self.show_save_generated_dialog, state=tk.DISABLED)
        self.save_gen_btn.grid(row=0, column=1, padx=5)

        
        ttk.Label(parent, text="Strength:", font=NORMAL_FONT).pack(pady=(10, 0))
        self.gen_strength = ttk.Label(parent, text="Select generation type.", font=BUTTON_FONT, foreground="yellow",
                                      background=PRIMARY_COLOR)
        self.gen_strength.pack(pady=5)

       
        control_frame = tk.Frame(parent, bg=PRIMARY_COLOR)
        control_frame.pack(pady=15)
        
      
        ttk.Label(control_frame, text="Complex String (8, 12, 16):", font=NORMAL_FONT).grid(row=0, column=0, padx=5, pady=5, sticky="w") # Adjusted padx
        self.gen_length = ttk.Combobox(control_frame, values=[8, 12, 16], width=5, state="readonly")
        self.gen_length.set(16)
        self.gen_length.grid(row=0, column=1, padx=5, pady=5)
      
        ttk.Button(control_frame, text="Generate Password", command=lambda: self.handle_generation('C')).grid(row=0, column=2, padx=5, pady=5) 

       
        ttk.Label(control_frame, text="Custom Passphrase Word:", font=NORMAL_FONT).grid(row=1, column=0, padx=5, pady=5, sticky="w") # Adjusted padx
       
        self.gen_user_word = ttk.Entry(control_frame, width=15, font=NORMAL_FONT, 
                                       background=SECONDARY_COLOR, foreground=INPUT_TEXT_COLOR)
        self.gen_user_word.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Generate Passphrase", command=lambda: self.handle_generation('P')).grid(row=1, column=2, padx=5, pady=5) 
        
        
        help_frame = tk.Frame(parent, bg=PRIMARY_COLOR)
        
        help_frame.pack(pady=(30, 10), padx=10, fill='x') 
        
        
        ttk.Button(help_frame, text="Why Choosing a Secure Password Is So Important", 
                   command=self.open_password_education_link).pack(fill='x', padx=20)


    def show_save_generated_dialog(self):
        
        
        password_to_save = self.gen_output.get()
        if not password_to_save:
            messagebox.showwarning("Error", "Please generate a password first.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Save Generated Password")
        dialog.configure(bg=SECONDARY_COLOR)
        
        
        ttk.Label(dialog, text="Name:", font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        name_entry = ttk.Entry(dialog, width=30, font=NORMAL_FONT, background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR)
        name_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")

        ttk.Label(dialog, text="URL:", font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        url_entry = ttk.Entry(dialog, width=30, font=NORMAL_FONT, background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR)
        url_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")

        ttk.Label(dialog, text="Username:", font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        username_entry = ttk.Entry(dialog, width=30, font=NORMAL_FONT, background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR)
        username_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        ttk.Label(dialog, text="Password:", font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(dialog, width=30, font=NORMAL_FONT, state='readonly', textvariable=tk.StringVar(value=password_to_save), background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR).grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="ew")


        def save_and_close():
            name = name_entry.get().strip()
            url = url_entry.get().strip()
            username = username_entry.get().strip()
            
            if not name or not url or not username:
                messagebox.showerror("Input Error", "Name, URL, and Username must be filled.")
                return

            
            current_date_str = date.today().strftime("%Y-%m-%d")

            
            encrypted_password = encrypt_data(password_to_save)

            new_entry = {
                "name": name,
                "url": url,
                "username": username,
                "password_encrypted": encrypted_password,
                "created_at": current_date_str # NEW KEY
            }
            passwords.append(new_entry)
            save_passwords_to_vault()
            self.refresh_vault_display()
            dialog.destroy()
            messagebox.showinfo("Success", f"Password for '{name}' saved and encrypted.")
            
            self.notebook.select(2) 
        
        
        dialog.bind('<Return>', lambda event: save_and_close())


        ttk.Button(dialog, text="Save and Close", command=save_and_close).grid(row=4, column=0, columnspan=3, pady=10)


    def handle_generation(self, gen_type):
        """Handles the logic for both complex string and passphrase generation."""
        self.gen_output.config(state='normal')
        self.gen_output.delete(0, tk.END)
        self.save_gen_btn.config(state=tk.DISABLED) # Disable save until new password is ready
        password = None

        if gen_type == 'C':
            try:
                length = int(self.gen_length.get())
                password = generate_password(length)
            except ValueError:
                messagebox.showerror("Input Error", "Please select a valid password length.")
                return
        
        elif gen_type == 'P':
            user_word = self.gen_user_word.get().strip()
            password = generate_passphrase(user_word=user_word)

        if password:
            self.gen_output.insert(0, password)
            self.gen_output.config(state='readonly')
            strength, _ = check_password_strength(password)
            self.gen_strength.config(text=f"Strength: {strength}", foreground=self.get_strength_color(strength))
            self.save_gen_btn.config(state=tk.NORMAL) 
        else:
            self.gen_strength.config(text="Generation Failed", foreground=ERROR_COLOR)


    def setup_validator_tab(self, parent):
        ttk.Label(parent, text="Enter Password to Validate:", font=HEADER_FONT).pack(pady=(15, 5))
        
        
        self.val_input = ttk.Entry(parent, width=50, font=NORMAL_FONT, 
                                   background=SECONDARY_COLOR, foreground=INPUT_TEXT_COLOR)
        self.val_input.pack(pady=5, padx=10)
        
        
        self.val_input.bind('<Return>', lambda event: self.validate_password())
        
        
        ttk.Button(parent, text="Check Strength", command=self.validate_password).pack(pady=10)

        
        ttk.Label(parent, text="Strength Rating:", font=NORMAL_FONT).pack(pady=(10, 0))
        self.val_strength = ttk.Label(parent, text="Rating: ---", font=BUTTON_FONT, foreground="yellow",
                                      background=PRIMARY_COLOR)
        self.val_strength.pack(pady=5)
        
        
        ttk.Label(parent, text="Detailed Feedback:", font=NORMAL_FONT).pack(pady=(10, 0))
        
        self.val_feedback = tk.Text(parent, height=8, width=50, font=NORMAL_FONT, 
                                    bg=SECONDARY_COLOR, fg=TEXT_COLOR, state='disabled')
        self.val_feedback.pack(pady=5, padx=10)

    def validate_password(self):
       
        password = self.val_input.get()
        if not password:
            messagebox.showwarning("Input Missing", "Please enter a password to validate.")
            return

        
        is_pwned, pwned_count = check_for_pwned_status(password)
        
        if is_pwned:
            strength = "UNSAFE (PWNED)"
            feedback_text = f"• CRITICAL: This password has been found in data breaches {pwned_count:,} times.\n"
            feedback_text += "(Source: haveibeenpwned/passwords)"
        elif pwned_count == -1:
             strength, feedback_text = check_password_strength(password)
             feedback_text = "• WARNING: HIBP breach check failed (no internet or API issue).\n" + feedback_text
        else:
           
            strength, feedback_text = check_password_strength(password)
            
           
            feedback_text = f"• SECURITY: Password NOT found in known data breaches (HIBP check).\n" + feedback_text
            
            
            feedback_text += "\n(Breach Check Source: haveibeenpwned/passwords)"

        self.val_strength.config(text=f"Rating: {strength}", foreground=self.get_strength_color(strength))
        
        self.val_feedback.config(state='normal')
        self.val_feedback.delete(1.0, tk.END)
        self.val_feedback.insert(tk.END, feedback_text)
        self.val_feedback.config(state='disabled')

    
    def check_for_reuse(self):
        """Checks the vault for any repeated passwords (Password Evolution)."""
        
        if not passwords:
            messagebox.showinfo("Reuse Check", "The vault is empty. Nothing to check.")
            return

        password_map: Dict[str, List[str]] = {}
        for entry in passwords:
           
            decrypted_pwd = decrypt_data(entry['password_encrypted'])
            
            
            pwd_hash = hashlib.sha256(decrypted_pwd.encode()).hexdigest()
            
            if pwd_hash not in password_map:
                password_map[pwd_hash] = []
            
            password_map[pwd_hash].append(entry['name']) 

        reuse_detected = {pwd_hash: names for pwd_hash, names in password_map.items() if len(names) > 1}

        if reuse_detected:
            message = "⚠️ WARNING: Password reuse detected in the following entries:\n\n"
            for names in reuse_detected.values():
                message += f"• Used for: {', '.join(names)}\n"
            message += "\nIt is strongly recommended to use unique passwords for all accounts."
            messagebox.showwarning("Security Alert: Password Reuse", message)
        else:
            messagebox.showinfo("Security Status", "✅ No password reuse detected. Excellent security practice!")
            
    
    def check_for_expired_passwords(self):
        
        
        if not passwords:
            messagebox.showinfo("Expiration Check", "The vault is empty. Nothing to check.")
            return

        expired_entries: List[Dict[str, str]] = [] 
        current_date = date.today() 
        
        expiration_threshold = timedelta(days=180) 

        for entry in passwords:
            created_at_str = entry.get("created_at")
            
            is_expired = False
            
            if not created_at_str or created_at_str == "2020-01-01":
                
                is_expired = True
                
            else:
                try:
                    created_date = date.fromisoformat(created_at_str)
                    age = current_date - created_date
                    
                    
                    if age > expiration_threshold:
                         is_expired = True
                    
                except ValueError:
                    
                    is_expired = True
            
            if is_expired:
                expired_entries.append(entry)

        
        
        if expired_entries:
            message = "⚠️ WARNING: The following entries are **older than 6 months** or have no date record:\n\n"
            
            for entry in expired_entries:
                entry_name = entry['name']
                created_at_str = entry.get("created_at")
                
                status = "Expired (Over 6 Months Old)"
                if not created_at_str or created_at_str == "2020-01-01":
                    status = "VERY OLD (No date stamp found)"
                
                message += f"• **{entry_name}** ({status})\n"
            
            message += "\nIt is strongly recommended to update these passwords for continued security. Undated entries must be updated to set a current date stamp."
            messagebox.showwarning("Security Alert: Password Expiration", message)
        else:
            messagebox.showinfo("Security Status", "✅ All passwords in the vault are less than 6 months old.")

    
    def show_update_entry_dialog(self):
        """
        Opens a dialog pre-filled with the selected entry's data, allowing the user 
        to update the name, URL, username, or password, and resets the date.
        """
        selected_items = self.tree.selection()
        
        if not selected_items:
            messagebox.showwarning("Update Error", "Please select an entry to update its password/details.")
            return

        if len(selected_items) > 1:
            messagebox.showwarning("Update Error", "Please select only ONE entry to update.")
            return
            
        item_id = selected_items[0]
        
        
        all_item_ids = self.tree.get_children()
        try:
            index = all_item_ids.index(item_id)
        except ValueError:
            messagebox.showerror("Internal Error", "Could not find selected item in vault list.")
            return
            
        if not (0 <= index < len(passwords)):
            messagebox.showerror("Internal Error", "Invalid index found for selected item.")
            return

        
        entry_to_update = passwords[index]
        
        
        decrypted_password = self.tree.item(item_id, 'tags')[1]
        
        
        
        dialog = tk.Toplevel(self)
        dialog.title(f"Update Entry: {entry_to_update['name']}")
        dialog.configure(bg=SECONDARY_COLOR)
        
        labels = ["Name:", "URL:", "Username:", "Password:"]
        entries = {}
        initial_values = {
            "Name:": entry_to_update['name'],
            "URL:": entry_to_update['url'],
            "Username:": entry_to_update['username'],
            "Password:": decrypted_password
        }
        
        for i, text in enumerate(labels):
            ttk.Label(dialog, text=text, font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=i, column=0, padx=5, pady=5, sticky="w")
            entries[text] = ttk.Entry(dialog, width=30, font=NORMAL_FONT, background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR)
            entries[text].insert(0, initial_values[text])
            entries[text].grid(row=i, column=1, padx=5, pady=5, sticky="ew")

        
        gen_btn = ttk.Button(dialog, text="Generate Passphrase", 
                   command=lambda: self.generate_and_insert(entries["Password:"]))
        gen_btn.grid(row=3, column=2, padx=5, pady=5)
        
        
        save_btn = ttk.Button(dialog, text="Save Changes & Update Date", 
                   command=lambda: self.save_updated_entry(dialog, entries, entry_to_update))
        save_btn.grid(row=4, column=0, columnspan=3, pady=10)
        
        
        dialog.bind('<Return>', lambda event: self.save_updated_entry(dialog, entries, entry_to_update))

    def save_updated_entry(self, dialog, entries, old_entry):
        
        name = entries["Name:"].get().strip()
        url = entries["URL:"].get().strip() 
        username = entries["Username:"].get().strip()
        new_password_raw = entries["Password:"].get()
        
        if not name or not url or not username or not new_password_raw:
            messagebox.showerror("Input Error", "All fields must be filled.")
            return

        
        old_password_raw = decrypt_data(old_entry['password_encrypted'])
        
        encrypted_password = old_entry['password_encrypted']
        
        password_changed = False
        if new_password_raw != old_password_raw:
           
            encrypted_password = encrypt_data(new_password_raw)
            password_changed = True

        
        old_entry['name'] = name
        old_entry['url'] = url
        old_entry['username'] = username
        old_entry['password_encrypted'] = encrypted_password
        
        
        old_entry['created_at'] = date.today().strftime("%Y-%m-%d")

        
        save_passwords_to_vault()
        
        
        self.refresh_vault_display()
        dialog.destroy()
        
        message = f"Entry for '{name}' successfully updated."
        if password_changed:
            message += "\nNew password encrypted and creation date reset."
        else:
             message += "\nDetails updated and creation date reset (Password was unchanged)."

        messagebox.showinfo("Success", message)


    def handle_checkbox_click(self, event):
        """Toggles the checkmark on click and updates the checked_items list."""
        
        
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell" and region != "tree" and region != "heading":
            return
            
        column = self.tree.identify_column(event.x)
        
        if column != "#0": 
            return

        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return

        
        tags = list(self.tree.item(item_id, 'tags'))
        is_checked = 'checked' in tags

        
        if is_checked:
            
            self.tree.item(item_id, tags=('unchecked', self.tree.item(item_id, 'tags')[1]))
            self.tree.item(item_id, image=self.check_box_empty)
            if item_id in self.checked_items:
                del self.checked_items[item_id]
        else:
           
            self.tree.item(item_id, tags=('checked', self.tree.item(item_id, 'tags')[1]))
            self.tree.item(item_id, image=self.check_box_checked)
            self.checked_items[item_id] = True 

    def handle_column_click(self, event):
        
        
        item_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)

        if not item_id:
            
            return self.handle_checkbox_click(event)

        
        if column_id == '#0':
            return self.handle_checkbox_click(event)
            
        
        self.tree.selection_set(item_id)
        
        
        values = self.tree.item(item_id, 'values')
        
        decrypted_password = self.tree.item(item_id, 'tags')[1]
        
        
        
        content_to_copy = None
        
        
        if column_id == '#3' and len(values) >= 3:
            content_to_copy = values[2]
            message = "Username copied to clipboard."
        
       
        elif column_id == '#4' and decrypted_password:
            content_to_copy = decrypted_password
            message = "Password copied to clipboard."
            
            
            messagebox.showinfo("Password Revealed", 
                                f"Name: {values[0]}\n"
                                f"URL: {values[1]}\n" 
                                f"Username: {values[2]}\n"
                                f"Password: {decrypted_password}\n\n"
                                f"Password copied to clipboard.")
        
       
        if content_to_copy:
            self.clipboard_clear()
            self.clipboard_append(content_to_copy)
            self.update()
            
            if column_id != '#4':
                 messagebox.showinfo("Copied", message)
        
    def unified_import_gui(self):
        """
        Handles importing both encrypted J.A.R.V.I.S. files and plaintext CSV files
        by trying the encrypted format first and falling back to plaintext.
        """
        if not master_password_set:
            messagebox.showerror("Error", "Vault must be unlocked first to import.")
            return
            
       
        filepath = filedialog.askopenfilename(defaultextension=".csv",
                                              filetypes=[("Unified CSV Import (J.A.R.V.I.S. Encrypted or Plaintext)", "*.csv"), 
                                                         ("All Files", "*.*")])
        if not filepath:
            return

       
        messagebox.showinfo("Importing", "Attempting to import as Encrypted J.A.R.V.I.S. Vault...")
        if _process_encrypted_csv(filepath, True):
            save_passwords_to_vault() 
            self.refresh_vault_display()
            messagebox.showinfo("Import Success", "Successfully imported and appended entries from the **Encrypted Vault** file.")
            return

        

        messagebox.showinfo("Import Attempt", "Encrypted import failed. Attempting to import as **Plaintext CSV**...")
        imported_count = _process_plaintext_csv(filepath)
        
        if imported_count > 0:
            save_passwords_to_vault()
            self.refresh_vault_display()
            messagebox.showinfo("Import Success", f"Successfully imported and **encrypted** {imported_count} new entries from the **Plaintext CSV**.")
        elif imported_count == 0:
            messagebox.showinfo("Import Info", "The file was read, but no new entries were found.")
        elif imported_count == -1:
             
             pass

    def setup_vault_tab(self, parent):
        
        
        tree_frame = tk.Frame(parent, bg=PRIMARY_COLOR)
        tree_frame.pack(pady=10, padx=10, expand=True, fill="both")
        
        
        self.tree = ttk.Treeview(tree_frame, columns=("Name", "URL", "Username", "Password"), 
                                 show="tree headings", height=10, selectmode='browse') 
        
        
        self.tree.column("#0", anchor='center', width=30, stretch=tk.NO)
        self.tree.heading("#0", text="select")

        
        self.tree.heading("Name", text="Name")
        self.tree.heading("URL", text="URL") 
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        
        
        self.tree.column("Name", width=110, anchor='center')
        self.tree.column("URL", width=110, anchor='center') 
        self.tree.column("Username", width=110, anchor='center')
        self.tree.column("Password", width=110, anchor='center')
        
        self.tree.pack(side="left", expand=True, fill="both")
        
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        
        self.refresh_vault_display()
        
        
        self.tree.bind('<Button-1>', self.handle_column_click)
        
        
        
        button_bar = tk.Frame(parent, bg=PRIMARY_COLOR)
        button_bar.pack(pady=(0, 10), padx=10, fill='x')
        
        
        inner_frame = tk.Frame(button_bar, bg=PRIMARY_COLOR)
        inner_frame.pack(side=tk.TOP, anchor=tk.CENTER, pady=5)
        
       
        
        
        inner_frame.grid_columnconfigure(0, weight=1)
        inner_frame.grid_columnconfigure(1, weight=1)
        
        
        ttk.Button(inner_frame, text="Add", command=self.show_add_entry_dialog).grid(row=0, column=0, padx=5, pady=2, sticky="ew")
        ttk.Button(inner_frame, text="Remove", command=lambda: self.remove_entry_multi()).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        
        ttk.Button(inner_frame, text="Check for Reused Passwords", command=self.check_for_reuse).grid(row=1, column=0, padx=5, pady=2, sticky="ew") 
        ttk.Button(inner_frame, text="Check for Expired", command=self.check_for_expired_passwords).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        
        ttk.Button(inner_frame, text="Update Password", command=self.show_update_entry_dialog).grid(row=2, column=0, columnspan=2, padx=5, pady=2, sticky="ew")
        
        
        ttk.Button(inner_frame, text="Export", command=self.export_encrypted_vault_gui).grid(row=3, column=0, padx=5, pady=2, sticky="ew")
        
        ttk.Button(inner_frame, text="Import", command=self.unified_import_gui).grid(row=3, column=1, padx=5, pady=2, sticky="ew")

    def remove_entry_multi(self):
        
        item_ids_to_remove = list(self.checked_items.keys())

        if not item_ids_to_remove:
            messagebox.showwarning("Selection Missing", "Please check one or more entries to remove.")
            return

        
        all_item_ids = self.tree.get_children()
        
        
        indices_to_remove = sorted([all_item_ids.index(item_id) for item_id in item_ids_to_remove], reverse=True)
        
        
        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to permanently delete {len(item_ids_to_remove)} checked entry(s)?"):
            
            
            for index in indices_to_remove:
                if 0 <= index < len(passwords):
                    del passwords[index]
            
            
            save_passwords_to_vault()
            
            
            self.checked_items.clear()
            
            
            self.refresh_vault_display()
            messagebox.showinfo("Success", f"{len(item_ids_to_remove)} entry(s) removed.")

    def refresh_vault_display(self):
        """Clears and re-populates the Treeview with current vault data."""
        self.tree.delete(*self.tree.get_children())
        self.checked_items.clear() 
        
        if passwords:
            for i, entry in enumerate(passwords):
                decrypted_password = decrypt_data(entry['password_encrypted'])
                
               
                display_password = "•" * max(8, len(decrypted_password))
                
                
                item_id = self.tree.insert("", tk.END, text="", 
                                 image=self.check_box_empty,
                                 values=(entry['name'], entry['url'], entry['username'], display_password),
                                 tags=('unchecked', decrypted_password)) # Store decrypted password and state in tags
        
            
    def show_add_entry_dialog(self):
        
        if not master_password_set:
            messagebox.showerror("Error", "Vault must be unlocked first.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Add New Vault Entry")
        
        dialog.configure(bg=SECONDARY_COLOR)
        
        
        labels = ["Name:", "URL:", "Username:", "Password:"]
        entries = {}
        
        for i, text in enumerate(labels):
            ttk.Label(dialog, text=text, font=NORMAL_FONT, background=SECONDARY_COLOR, foreground=TEXT_COLOR).grid(row=i, column=0, padx=5, pady=5, sticky="w")
            
            entries[text] = ttk.Entry(dialog, width=30, font=NORMAL_FONT, background=PRIMARY_COLOR, foreground=INPUT_TEXT_COLOR)
            entries[text].grid(row=i, column=1, padx=5, pady=5, sticky="ew")

       
        ttk.Button(dialog, text="Generate Passphrase", 
                   command=lambda: self.generate_and_insert(entries["Password:"])).grid(row=3, column=2, padx=5, pady=5)
        
       
        ttk.Button(dialog, text="Save Entry", 
                   command=lambda: self.save_new_entry(dialog, entries)).grid(row=4, column=0, columnspan=3, pady=10)
        
        
        dialog.bind('<Return>', lambda event: self.save_new_entry(dialog, entries))


    def generate_and_insert(self, password_entry):
        
        user_word = simpledialog.askstring("Passphrase", "Enter a memorable word (optional):")
        if user_word is not None:
            new_password = generate_passphrase(user_word=user_word)
            password_entry.delete(0, tk.END)
            password_entry.insert(0, new_password)
            
    def save_new_entry(self, dialog, entries):
       
        name = entries["Name:"].get().strip() # NEW
        url = entries["URL:"].get().strip() 
        username = entries["Username:"].get().strip()
        password_raw = entries["Password:"].get()
        
        if not name or not url or not username or not password_raw:
            messagebox.showerror("Input Error", "All fields must be filled.")
            return
            
        
        current_date_str = date.today().strftime("%Y-%m-%d")

        encrypted_password = encrypt_data(password_raw)

        new_entry = {
            "name": name, 
            "url": url, 
            "username": username,
            "password_encrypted": encrypted_password,
            "created_at": current_date_str 
        }
        passwords.append(new_entry)
        save_passwords_to_vault()
        self.refresh_vault_display()
        dialog.destroy()
        messagebox.showinfo("Success", f"Entry for '{name}' saved and encrypted.")

    def export_encrypted_vault_gui(self):
        
        if not master_password_set:
            messagebox.showerror("Error", "Vault must be unlocked first.")
            return
            
        if not os.path.exists(DB_FILE) or not passwords:
             messagebox.showinfo("Export Info", "Vault is empty or file not found. Nothing to export.")
             return

        filepath = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                initialfile=CSV_FILE,
                                                filetypes=[("Encrypted Vault CSV File", "*.csv")]) 
        if not filepath:
            return
            
        try:
            
            import shutil
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True) 
            shutil.copyfile(DB_FILE, filepath)
            messagebox.showinfo("Export Success", 
                                f"Successfully created SECURE encrypted export to:\n{filepath}\n\n"
                                "This file is protected and requires your Master Password to be imported back into J.A.R.V.I.S.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to create encrypted backup: {e}")

    

    def copy_to_clipboard(self):
        
        try:
            password = self.gen_output.get()
            if password:
                self.clipboard_clear()
                self.clipboard_append(password)
                self.update()
                messagebox.showinfo("Copied", "Password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy: {e}")

    def get_strength_color(self, strength: str) -> str:
        
        if strength in ["EXCEPTIONAL", "VERY STRONG"]:
            return "#4CAF50" 
        elif strength == "STRONG":
            return "#FFC107" 
        elif strength == "MEDIUM":
            return "#FF9800" 
        elif strength == "UNSAFE (PWNED)":
            return ERROR_COLOR 
        else:
            return ERROR_COLOR 

    def on_closing(self):
        
        if master_password_set:
            save_passwords_to_vault()
        self.destroy()

if __name__ == "__main__":
    app = JarvisTool()
    print("\n--- FRIDAY GUI Started ---")
    app.mainloop()
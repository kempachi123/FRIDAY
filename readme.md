# 🔒 JARVIS: Secure Password Tool (Python/Tkinter)

JARVIS is a modern, cross-platform desktop password manager built entirely in Python using the Tkinter GUI library. It uses a Black-themed interface (Inspired by the JARVIS AI) and robust security practices, including **Master Password derivation** and **Fernet encryption**.

## ✨ Key Features

* **🔒 Local Security:** Uses a strong Master Password, salt-based key derivation (PBKDF2-like), and **Fernet symmetric encryption** for vault storage.
* **🔑 Secure Generation:** Generates strong, random complex passwords and user-friendly, memorable passphrases.
* **🔍 Advanced Validation:**
    * Integrates with the **Have I Been Pwned (HIBP)** API using k-Anonymity (SHA-1 prefix search) to check for compromised passwords.
    * Checks against a local list of **Top 10,000 Common Passwords**.
    * Provides detailed strength feedback based on complexity and length.
* **🔄 Vault Manager:**
    * Tracks password creation dates and flags entries **older than 6 months** as expired (recommendation for rotation).
    * A dedicated tool to check for **Password Reuse** across accounts.
    * Unified Import/Export supporting both encrypted and plaintext CSV files.
    * GUI-based multi-entry deletion and detail updating.

## 🚀 Getting Started

### Prerequisites

You need Python 3.x installed on your system.

### Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/YOUR_GITHUB_USERNAME/JarvisTool.git](https://github.com/YOUR_GITHUB_USERNAME/JarvisTool.git)
    cd JarvisTool
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Setup the Top Passwords List (Optional but Recommended for Full Security):**
    * Create a directory named `data` in the project root.
    * Download a list of common passwords (e.g., the [Rockyou list, filtered to top 10k](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)) and save it as `data/top10k.txt`.

### Running the Application

```bash
python main.py
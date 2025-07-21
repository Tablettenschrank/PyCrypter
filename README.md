# PyCrypter: A Command-Line Encryption Tool

This is a command-line tool for encrypting and decrypting your files, folders, and text snippets. It's built to be secure, work on any operating system, and give you control over how it operates through a simple config file.

---

## Project Status & Disclaimer

> **Note:** This project is a **work in progress**. While the core features for encryption and decryption are stable and work very well, new functionality is being planned and the code is subject to refactoring.

This is a personal hobby project that I work on in my spare time, so updates might not be frequent. It's a way for me to explore concepts in cryptography, file handling, and application structure in Python. Always make sure you have backups of your important data.

---

## Features

* **Encrypt Anything:** Handle individual files, entire folders (either file-by-file or as a single archive), and simple text messages.
* **Strong Security:**
    * Uses the battle-tested `cryptography` library.
    * Every encryption gets a unique, random salt to ensure identical files look different when encrypted.
    * Uses PBKDF2 with a high, configurable number of iterations to protect against password guessing.
    * Includes a password strength checker (`zxcvbn`) to prevent you from accidentally using a weak password.
* **Handles Large Files:** Encrypts and decrypts large files by processing them in smaller chunks ("streaming"), so it uses very little memory, even for files over 100 GB.
* **Performance:** Uses multiple CPU cores (`multiprocessing`) to speed up encrypting or decrypting large batches of files.
* **File Integrity:**
    * Automatically shows a SHA-256 checksum after encrypting a file.
    * Includes a tool to verify the checksum of any file (SHA-256 or SHA-512) to make sure it hasn't been corrupted or tampered with.
* **User-Friendly Terminal:**
    * Clear progress bars for all long-running operations that show speed, progress, and estimated time remaining.
    * Highly configurable through the `config.ini` file.
    * Still works even if optional packages (`tqdm` for progress bars, `psutil` for system stats) are not installed.

---

## Requirements

* Python 3.10+
* The external libraries listed in `requirements.txt`.

---

## 🚀 Installation & Usage

This tool can be used in two ways: by running the standalone executable (for most users) or by running the Python script directly (for developers).

### The Easy Way (Recommended)

This is the fastest way to use the tool without needing to install Python or any packages.

1.  **Download:** Get the `PyCrypter.exe` (or the corresponding file for your OS) from the project's "Releases" page.
2.  **Run:** Place the executable in any folder. The first time you run it, a default `config.ini` file will be created in the same folder.
3.  **Usage:** Open your terminal (like `cmd` or PowerShell) in the same folder as the `.exe` file and run it by typing its name:
    ```bash
    # On Windows PowerShell
    .\PyCrypter.exe

    # On Windows CMD
    PyCrypter.exe
    ```
    The interactive menu will then guide you through all options.

### For Developers (Running from source)

If you want to run the tool directly from its source code:

1.  **Prerequisites:** Ensure you have Python 3.10+ installed.
2.  **Clone:** Clone or download the repository.
3.  **Install Dependencies:** Open a terminal in the project folder and run:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run:** Start the application with:
    ```bash
    python main.py
    ```

---

## Usage

Run the application from your terminal:

```bash
python main.py
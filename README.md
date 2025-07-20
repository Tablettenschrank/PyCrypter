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

## Installation & Setup

1.  **Get the code:**
    Clone the repository or download the ZIP file.

2.  **Install the packages:**
    Open a terminal in the project folder and run:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration:**
    The first time you run the program, it will automatically create a `config.ini` file with default settings if one isn't found. It's a good idea to look through this file and adjust it to your needs.

---

## Usage

Run the application from your terminal:

```bash
python main.py
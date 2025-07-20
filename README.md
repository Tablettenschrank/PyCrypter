# 🔒 PyCrypter - A Versatile Command-Line Encryption Tool

PyCrypter is a powerful, cross-platform command-line tool built with Python for securely encrypting and decrypting files, folders, and text messages. It is designed to be robust, secure, and highly configurable, making it suitable for protecting sensitive data.

This tool was built with a focus on modern security practices and a flexible architecture that supports everything from single files to large batch operations.

---

## ⚠️ Project Status & Disclaimer

> **Note:** This project is a **work in progress**. While the core features for encrypting and decrypting files, folders, and text are stable and work very well, new functionality is being planned and the code is subject to refactoring.

Please note that this is a personal hobby project. I work on it in my spare time, so updates may be infrequent. It primarily serves as a learning ground for exploring concepts in cryptography, file handling, and application structure in Python. Always ensure you have backups of important data.

---

## ✨ Key Features

* **Multiple Encryption Modes:**
    * **Files:** Encrypt or decrypt individual files of any size.
    * **Folders:**
        * *In-Place:* Encrypt/decrypt every file within a folder and its subdirectories.
        * *As Archive:* Securely package an entire folder into a single encrypted archive.
    * **Text:** Quickly encrypt and decrypt text messages or passwords for secure sharing.
* **Strong Security:**
    * Uses the industry-standard `cryptography` library (featuring Fernet/AES).
    * **Dynamic Salts:** Every encryption uses a unique, random salt to protect against pre-computation attacks.
    * **Strong Key Derivation:** Implements PBKDF2 with a high, configurable number of iterations to make password cracking difficult.
    * **Password Strength Checking:** Integrates `zxcvbn` to prevent the use of weak passwords.
* **High Performance & Robustness:**
    * **Large File Support:** Utilizes a streaming approach to encrypt/decrypt files of any size with minimal RAM usage.
    * **Multiprocessing:** Uses multiple CPU cores to dramatically speed up batch processing of many files.
    * **File Integrity:** Automatically displays SHA-256 checksums after encryption and provides a tool to verify them.
* **User-Friendly CLI:**
    * **Progress Bars:** Detailed progress bars (`tqdm`) for all long-running operations, showing speed, ETA, and current file.
    * **Highly Configurable:** Almost all features (algorithms, performance, UI) can be tweaked via a simple `config.ini` file.
    * **Optional Dependencies:** The tool remains functional even without `tqdm` or `psutil`, simply disabling the quality-of-life features they provide.

---

## ⚙️ Requirements

* Python 3.10+
* External libraries listed in `requirements.txt`:
    * `cryptography` (for encryption)
    * `zxcvbn-python` (for password strength)
    * `tqdm` (optional, for progress bars)
    * `psutil` (optional, for debug stats)

---

## 🚀 Installation & Setup

1.  **Clone the repository (or download the ZIP):**
    ```bash
    git clone <your-repo-url>
    cd PyCrypter
    ```

2.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration:**
    The program will automatically create a default `config.ini` file on its first run if one is not found. It is highly recommended to review this file and adjust settings like `pbkdf2_iterations` to your needs.

---

## ▶️ Usage

Run the application from your terminal in the project's root directory:

```bash
python main.py
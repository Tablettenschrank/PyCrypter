# PyCrypter: A Command-Line Encryption Tool

This is a command-line tool for encrypting and decrypting your files, folders, and text snippets. It's built to be secure, work on any operating system, and give you control over how it operates through a simple config file.

---

## ⚠️ Project Status & Disclaimer

> **Note:** This project is a **Work In Progress (WIP)**. While the core features for encrypting and decrypting files, folders, and text are stable and work very well, new functionality is being planned and the code is subject to refactoring.

This project is a personal hobby project and serves as a practical environment for me to learn and improve skills in several key areas:
- **Python Development:** Applying concepts from basic scripting to advanced topics like multiprocessing, streaming, and secure coding practices.
- **Project Realization:** The process of taking a simple idea and building it into a complex, feature-rich command-line application.
- **AI Collaboration:** Learning to effectively prompt and collaborate with an AI assistant. This includes a workflow of reviewing code myself, handing it to the AI for refinement, and debugging the results.
- **Testing & Debugging:** Actively finding and fixing bugs in an evolving codebase.

The project was developed in close collaboration with an AI assistant (see Acknowledgments for more details). Always ensure you have backups of your important data.

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

## Platform Support

This tool is developed using cross-platform Python libraries and is expected to run correctly on Windows, macOS, and Linux.

Currently, it is primarily tested on Windows. Formal testing and packaging for macOS and Linux are planned for the future but are not a current priority.

---

## Requirements

* Python 3.10+
* The external libraries listed in `requirements.txt`.

---

## Installation & Usage

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

#### Building the Executable

To package the application into a single `.exe` file for distribution, use `PyInstaller`. Run the following command from the project's root directory:

```bash
pyinstaller --name PyCrypter --onefile main.py
```
- `--name PyCrypter`: Sets the name of the final executable to `PyCrypter.exe`.
- `--onefile`: Bundles everything into a single file.
- `--add-data "config.ini;."`: Crucially includes the `config.ini` file in the bundle.

The final executable will be located in the `dist` folder.

PyInstaller automatically detects that `main.py` imports modules from the `src` directory and will bundle them into the final executable. The final `.exe` will be located in the `dist` folder.

---

## Acknowledgments

A significant part of this project's development, including architectural decisions, feature implementation, code refactoring, and debugging, was carried out in collaboration with an AI assistant (Google's Gemini). This project is an example of a human-AI partnership in software development.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Known Issues

### "Access is denied" Error on Folder Deletion

**Issue:**
Occasionally, especially on Windows, you might encounter a `[WinError 5] Access is denied` error. This can happen after any operation that creates and then quickly attempts to delete a folder, for example:
- During the final cleanup of the automated test suite.
- When encrypting a folder as an archive and choosing to delete the original folder.

**Cause:**
This is a common timing issue related to file system locks. The script performs many file operations very quickly. Sometimes, the operating system or a background process (like an antivirus scanner) hasn't fully released its lock on the *directory itself* when the script attempts to delete it. This can result in a state where the files *inside* the folder are successfully deleted, but the script fails when trying to remove the now-empty parent folder.

**Solution / Workaround:**
The program has a built-in retry mechanism that attempts to delete the folder several times. This **may sometimes resolve the timing issue, but it is not guaranteed**. If the error persists, the safest solution is to manually delete the folder after the script has finished its work.
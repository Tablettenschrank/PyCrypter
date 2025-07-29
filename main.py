import configparser
import os
import sys
import time
import multiprocessing
from pathlib import Path
from typing import Any, Dict

# Import the menu handlers from the 'src' package
from src.cli import (
    handle_file_menu,
    handle_folder_menu,
    handle_text_menu,
    handle_config_menu,
    handle_debug_menu,
)
from src.utils import get_title_suffix

# Load optional dependencies for startup information
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def create_default_config(config_path: Path) -> None:
    """Creates a default config.ini file if it doesn't exist."""
    print("INFO: 'config.ini' not found. Creating a new one with default settings...")
    
    # UPDATED: The default configuration content has been updated.
    default_config_content = """
[Settings]
# Choose your preferred symmetric encryption algorithm for password-based encryption.
# Currently only 'fernet' is implemented. AES-GCM will be implemented in the future.
default_algorithm = fernet

# The file extension for your encrypted files.
encrypted_file_extension = .tet

# Size of the dynamic salt in bytes. 16 is a secure standard.
salt_size_bytes = 16

# Default answer for the delete confirmation prompt after archiving a folder.
# Options: yes / no
default_delete_confirmation = yes

# --- Security Settings ---

# Number of iterations for the key derivation function (PBKDF2).
# Higher is more secure but slower. 600000 is a strong baseline.
pbkdf2_iterations = 600000

# When set to 'yes', the content of a folder is encrypted file-by-file
# BEFORE the folder is archived and encrypted as a whole.
# as for decryption, the folder is decrypted first, then each file inside, so usefull for 2 different passwords.
double_encryption_on_archive = no

# --- Performance Features ---

# Use multiple CPU cores to process files in parallel (for in-place and pattern encryption).
# Options: yes / no
enable_multiprocessing = yes

# Number of parallel processes to use. 
# 0 means use all available CPU cores, which is recommended.
worker_processes = 0

# Chunk size in Kilobytes for reading large files.
# A larger value can be slightly faster on fast drives (like SSDs) but uses more RAM.
# A smaller value uses less RAM, which can be better for older systems.
# 8192 KB = 8 MB. This is the current testing value (4 MB is the standard default).
chunk_size_kb = 8192

# --- RSA Settings (IN PROGRESS - NOT IMPLEMENTED YET) ---

# Default paths for RSA keys. Can be generated in the Key Management menu.
default_public_key_path = public_key.pem
default_private_key_path = private_key.pem

# --- Development Settings ---

# Enable debug mode to bypass password strength checks for testing purposes.
# WARNING: For testing only! Set to 'no' for real encryption.
debug_mode = no

[UI]
# Style of the progress bar.
# Options: unicode (modern style: ███), ascii (compatible style: ###)
progress_bar_style = unicode

# Select the user interface mode (IN PROGRESS - GUI NOT IMPLEMENTED YET).
# Options: cli (command-line, default), gui (graphical user interface) 
interface_mode = cli
"""
    try:
        config_path.write_text(default_config_content.strip(), encoding='utf-8')
        print("✅ Default 'config.ini' created successfully.")
        time.sleep(2)
    except (UnicodeEncodeError, PermissionError) as e:
        print(f"❌ Critical Error: Could not write to '{config_path}'. Error: {e}")
        print("INFO: As a fallback, the configuration content will be saved to 'config.txt'.")
        try:
            fallback_path = config_path.with_name('config.txt')
            fallback_path.write_text(default_config_content.strip(), encoding='ascii', errors='ignore')
            print(f"✅ Fallback file '{fallback_path.name}' created. Please rename it to 'config.ini' to continue.")
        except Exception as e2:
            print(f"❌ Fallback also failed: {e2}")
        sys.exit(1)


def main() -> None:
    """Main function to run the application's menu loop."""
    if not TQDM_AVAILABLE:
        print("INFO: Optional package 'tqdm' not found. Progress bars will be disabled.")
        time.sleep(2)
    if not PSUTIL_AVAILABLE:
        print("INFO: Optional package 'psutil' not found. System resource stats in debug mode will be disabled.")
        time.sleep(2)

    while True:
        try:
            config_path = Path('config.ini')
            if not config_path.exists():
                create_default_config(config_path)

            config = configparser.ConfigParser(interpolation=None)
            config.read(config_path)
            settings: Dict[str, Any] = {}
            for section in config.sections():
                settings.update(dict(config.items(section)))
        except Exception as e:
            print(f"Error loading config.ini: {e}")
            return
        
        title_suffix = get_title_suffix(settings)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"🔒 Python Encryption Tool - MAIN MENU 🔒{title_suffix}")
        print("=" * 45)
        print("  [1] Category: Files\n  [2] Category: Folders\n  [3] Category: Text Messages\n  [7] View/Edit Config\n  [8] Debug/Analysis Tools\n  [9] Exit Program")
        print("-" * 45)
        choice = input("Select a category: ")
        if choice == '1': handle_file_menu(settings)
        elif choice == '2': handle_folder_menu(settings)
        elif choice == '3': handle_text_menu(settings)
        elif choice == '7': handle_config_menu(settings)
        elif choice == '8': handle_debug_menu(settings)
        elif choice == '9': print("Goodbye! 👋"); break
        else: print("Invalid selection."); input("\nPress Enter...")

if __name__ == "__main__":
    if sys.platform != "win32":
        multiprocessing.set_start_method('spawn', force=True)
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user. 👋"); sys.exit(0)
    except Exception as e:
        print(f"\n\nAn unexpected critical error occurred: {e}")
        sys.exit(1)
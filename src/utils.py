import getpass
import os
import shutil
import sys
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict

try:
    from zxcvbn import zxcvbn
except ImportError:
    # This check is also in main.py, but included here for module integrity
    print("Error: 'zxcvbn' not found. Exiting.")
    sys.exit(1)

# --- Helper Functions ---

def format_duration(seconds: float) -> str:
    """Formats a duration in seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes, seconds = divmod(seconds, 60)
    return f"{int(minutes)} minute(s) and {seconds:.2f} seconds"

def open_file_in_editor(file_path: Path) -> None:
    """Opens a file with the system's default application for text files."""
    print(f"Attempting to open '{file_path}' with the default system editor...")
    try:
        if sys.platform == "win32":
            os.startfile(file_path)
        elif sys.platform == "darwin":
            subprocess.run(['open', file_path], check=True)
        else: # Linux and other POSIX
            subprocess.run(['xdg-open', file_path], check=True)
        print("Editor launched. The script will continue after you close the editor.")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"❌ Could not open the file. Please open '{file_path}' manually.")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

def get_password(config: Dict, confirm: bool = True, prompt_message: str = "Please enter your password: ") -> Optional[str]:
    """Securely prompts for a password, checks its strength, and asks for confirmation."""
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    if is_debug and confirm:
        print("\n-- WARNING: DEBUG MODE IS ON. Password strength check is disabled. --")
    while True:
        password = getpass.getpass(prompt_message)
        if not password:
            print("❌ An empty password is not allowed.")
            return None
        if not is_debug and confirm:
            strength = zxcvbn(password)
            if strength['score'] < 3:
                print(f"❌ Password is too weak (Score: {strength['score']}/4).")
                if feedback := strength['feedback']['warning']:
                    print(f"   Hint: {feedback}")
                for suggestion in strength['feedback'].get('suggestions', []):
                    print(f"   Suggestion: {suggestion}")
                print("Please try a stronger password.")
                continue
        if confirm:
            password_confirm = getpass.getpass("Confirm your password: ")
            if password != password_confirm:
                print("❌ The passwords do not match.")
            else:
                return password
        else:
            return password

def confirm_deletion(folder_path: Path, config: Dict) -> bool:
    """Asks the user for confirmation to delete the original folder, showing the default."""
    default = config.get('default_delete_confirmation', 'no').lower()
    prompt = f"Delete original folder '{folder_path}'? [Y[DEFAULT]/n]: " if default == 'yes' else f"Delete original folder '{folder_path}'? [y/N[DEFAULT]]: "
    answer = input(prompt).lower().strip()
    if answer == '':
        return default == 'yes'
    return answer in ['y', 'yes']

def get_title_suffix(config: Dict) -> str:
    """Returns a debug suffix for titles if debug mode is on."""
    if config.get('debug_mode', 'no').lower() == 'yes':
        return " [DEBUG]"
    return ""
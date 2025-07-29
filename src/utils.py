# src/utils.py
import getpass
import os
import re
import shutil
import sys
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Error: 'zxcvbn' not found. Exiting.")
    sys.exit(1)

# --- Path Validation ---
def validate_file_path(path_str: str, must_exist: bool = True) -> Optional[Path]:
    """Validate file path with comprehensive checks."""
    try:
        path = Path(path_str.strip()).resolve()
        
        # Check for empty input
        if not path_str.strip():
            print("❌ Empty path not allowed.")
            return None
            
        # Check for invalid characters (basic security)
        if any(char in str(path) for char in ['<', '>', '|', '\0']):
            print("❌ Invalid characters in path.")
            return None
            
        # Check path length (Windows compatibility)
        if len(str(path)) > 260:
            print("❌ Path too long (maximum 260 characters).")
            return None
            
        if must_exist:
            if not path.exists():
                print(f"❌ Path does not exist: {path}")
                return None
            if not path.is_file():
                print(f"❌ Path is not a file: {path}")
                return None
                
        # Check permissions
        parent = path.parent if not path.exists() else path
        if not os.access(parent, os.R_OK | os.W_OK):
            print(f"❌ No read/write permission: {path}")
            return None
            
        return path
    except (OSError, ValueError) as e:
        print(f"❌ Invalid path: {e}")
        return None

def validate_directory_path(path_str: str) -> Optional[Path]:
    """Validate directory path with comprehensive checks."""
    try:
        path = Path(path_str.strip()).resolve()
        
        if not path_str.strip():
            print("❌ Empty path not allowed.")
            return None
            
        if not path.exists():
            print(f"❌ Directory does not exist: {path}")
            return None
            
        if not path.is_dir():
            print(f"❌ Path is not a directory: {path}")
            return None
            
        if not os.access(path, os.R_OK | os.W_OK):
            print(f"❌ No read/write permission: {path}")
            return None
            
        return path
    except (OSError, ValueError) as e:
        print(f"❌ Invalid directory path: {e}")
        return None

# --- Helper Functions ---
def parse_size_string(size_str: str) -> Optional[int]:
    """Parses a size string like '50MB', '1.5GB' into bytes."""
    size_str = size_str.lower().strip()
    try:
        match = re.match(r'^(\d+\.?\d*)\s*([kmg]?b?)$', size_str)
        if not match:
            return None
        
        value_str, unit = match.groups()
        value = float(value_str)
        
        if unit.startswith('g'):
            multiplier = 1024**3
        elif unit.startswith('m'):
            multiplier = 1024**2
        elif unit.startswith('k'):
            multiplier = 1024
        else: # Assumes bytes if no unit
            multiplier = 1
        
        return int(value * multiplier)
    except (ValueError, TypeError):
        return None

def format_duration(seconds: float) -> str:
    if seconds < 60: return f"{seconds:.2f} seconds"
    minutes, seconds = divmod(seconds, 60)
    return f"{int(minutes)} minute(s) and {seconds:.2f} seconds"

def open_file_in_editor(file_path: Path) -> None:
    print(f"Attempting to open '{file_path}' with the default system editor...")
    try:
        if sys.platform == "win32": os.startfile(file_path)
        elif sys.platform == "darwin": subprocess.run(['open', file_path], check=True)
        else: subprocess.run(['xdg-open', file_path], check=True)
        print("Editor launched. The script will continue after you close the editor.")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"❌ Could not open the file. Please open '{file_path}' manually.")
    except Exception as e: print(f"❌ An unexpected error occurred: {e}")

def get_password(config: Dict, confirm: bool = True, prompt_message: str = "Please enter your password: ") -> Optional[str]:
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    if is_debug and confirm: print("\n-- WARNING: DEBUG MODE IS ON. Password strength check is disabled. --")
    while True:
        password = getpass.getpass(prompt_message)
        if not password: print("❌ An empty password is not allowed."); return None
        if not is_debug and confirm:
            strength = zxcvbn(password)
            if strength['score'] < 3:
                print(f"❌ Password is too weak (Score: {strength['score']}/4).")
                if feedback := strength['feedback']['warning']: print(f"   Hint: {feedback}")
                for suggestion in strength['feedback'].get('suggestions', []): print(f"   Suggestion: {suggestion}")
                print("Please try a stronger password."); continue
        if confirm:
            password_confirm = getpass.getpass("Confirm your password: ")
            if password != password_confirm: print("❌ The passwords do not match.")
            else: return password
        else: return password

def confirm_deletion(folder_path: Path, config: Dict) -> bool:
    default = config.get('default_delete_confirmation', 'no').lower()
    prompt = f"Delete original folder '{folder_path}'? [Y[DEFAULT]/n]: " if default == 'yes' else f"Delete original folder '{folder_path}'? [y/N[DEFAULT]]: "
    answer = input(prompt).lower().strip()
    return (answer == '') or (answer in ['y', 'yes']) if default == 'yes' else (answer in ['y', 'yes'])

def get_title_suffix(config: Dict) -> str:
    return " [DEBUG]" if config.get('debug_mode', 'no').lower() == 'yes' else ""
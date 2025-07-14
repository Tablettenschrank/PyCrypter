import os
import base64
import configparser
import getpass
import glob
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

# External dependency for password strength checking
try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Error: 'zxcvbn' library not found. Please install it using: pip install zxcvbn-python")
    sys.exit(1)

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- Cryptography and Hash Logic ---

def derive_key(password: str, salt: bytes, config: dict, key_length: int = 32) -> bytes:
    """Derives a cryptographic key from a password using PBKDF2."""
    iterations = int(config.get('pbkdf2_iterations', 600000))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, original_extension: str, password: str, config: dict) -> bytes:
    """
    Encrypts data and prepends metadata (salt size, salt, nonce, original extension).
    Returns the complete encrypted blob.
    """
    algorithm = config.get('default_algorithm', 'fernet')
    salt_size = int(config.get('salt_size_bytes', 16))
    if not (0 < salt_size < 256):
        raise ValueError("Salt size must be between 1 and 255.")
    
    salt_size_byte = salt_size.to_bytes(1, 'big')
    salt = os.urandom(salt_size)
    key = derive_key(password, salt, config)
    
    ext_bytes = original_extension.encode('utf-8')
    ext_len_byte = len(ext_bytes).to_bytes(1, 'big')
    payload_to_encrypt = ext_len_byte + ext_bytes + data
    
    if algorithm == 'aes-gcm':
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_payload = aesgcm.encrypt(nonce, payload_to_encrypt, None)
        return salt_size_byte + salt + nonce + encrypted_payload
    else: # Fallback to Fernet
        fernet = Fernet(base64.urlsafe_b64encode(key))
        encrypted_payload = fernet.encrypt(payload_to_encrypt)
        return salt_size_byte + salt + encrypted_payload

def decrypt_data(encrypted_blob: bytes, password: str, config: dict) -> Tuple[bytes, str]:
    """
    Decrypts a data blob by first reading its metadata (salt size).
    Returns a tuple of (decrypted_data, original_extension).
    """
    algorithm = config.get('default_algorithm', 'fernet')
    try:
        salt_size = int.from_bytes(encrypted_blob[0:1], 'big')
        salt = encrypted_blob[1 : 1 + salt_size]
        encrypted_payload = encrypted_blob[1 + salt_size :]
        
        key = derive_key(password, salt, config)

        if algorithm == 'aes-gcm':
            aesgcm = AESGCM(key)
            nonce, ciphertext = encrypted_payload[:12], encrypted_payload[12:]
            decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
        else: # Fallback to Fernet
            fernet = Fernet(base64.urlsafe_b64encode(key))
            decrypted_payload = fernet.decrypt(encrypted_payload)
            
        ext_len = int.from_bytes(decrypted_payload[0:1], 'big')
        original_extension = decrypted_payload[1 : 1 + ext_len].decode('utf-8')
        original_data = decrypted_payload[1 + ext_len :]
        
        return (original_data, original_extension)
        
    except (InvalidToken, TypeError, IndexError, ValueError):
        raise ValueError("Decryption failed. Wrong password/algorithm or corrupt data.")

def calculate_hash(file_path: Path, algorithm: str = 'sha256', block_size: int = 65536) -> Optional[str]:
    """Calculates the hash of a file and returns it as a hex string."""
    hasher = hashlib.new(algorithm)
    try:
        with file_path.open('rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

# --- Processing Functions ---

def process_single_file(file_path: Path, password: str, action: str, config: dict, unpack: bool = False) -> Optional[Path]:
    """Encrypts or decrypts a single file, with an option to auto-unpack archives."""
    try:
        if action == 'encrypt':
            encrypted_file_path = file_path.with_suffix(config['encrypted_file_extension'])
            original_data = file_path.read_bytes()
            encrypted_content = encrypt_data(original_data, file_path.suffix, password, config)
            encrypted_file_path.write_bytes(encrypted_content)
            file_path.unlink() # Delete original file
            
            print(f"✅ Encrypted successfully: {encrypted_file_path.name}")
            if checksum := calculate_hash(encrypted_file_path, 'sha256'):
                print(f"   └── SHA-256 Checksum: {checksum}")

        elif action == 'decrypt':
            encrypted_content = file_path.read_bytes()
            decrypted_content, original_ext = decrypt_data(encrypted_content, password, config)
            
            original_file_path = file_path.with_suffix(original_ext)
            original_file_path.write_bytes(decrypted_content)
            file_path.unlink() # Delete encrypted file
            
            if unpack and original_file_path.suffix == '.zip':
                print(f"✅ Archive decrypted. Unpacking '{original_file_path.name}'...")
                extract_dir = original_file_path.parent
                shutil.unpack_archive(original_file_path, extract_dir)
                original_file_path.unlink() # Delete the temporary .zip file
                unpacked_folder_path = extract_dir / original_file_path.stem
                print("✅ Unpacking complete.")
                return unpacked_folder_path
            else:
                print(f"✅ Decrypted successfully: {original_file_path.name}")
                return original_file_path
    except (ValueError, FileNotFoundError) as e:
        print(f"❌ Error: {e}")
    return None

def process_folder_in_place(path: Path, password: str, action: str, config: dict) -> None:
    """Encrypts or decrypts all files within a folder."""
    print("-" * 30)
    print(f"{action.capitalize()}ing all files in folder '{path}'...")
    extension = config['encrypted_file_extension']
    for item in path.rglob('*'):
        if item.is_file():
            if action == 'encrypt' and item.suffix != extension:
                process_single_file(item, password, 'encrypt', config)
            elif action == 'decrypt' and item.suffix == extension:
                process_single_file(item, password, 'decrypt', config)
    print("Operation finished.")

def create_and_encrypt_archive(path_str: str, password: str, config: dict) -> None:
    """Creates an archive based on the path specifier and encrypts it."""
    path_str, archive_contents_only = path_str.strip(), False
    clean_path_str = path_str
    if path_str.endswith(('/*','\\*')):
        clean_path_str, archive_contents_only = path_str[:-2], True
    elif path_str.endswith(('/', '\\')):
        clean_path_str, archive_contents_only = path_str[:-1], True
    
    clean_path = Path(clean_path_str)
    if not clean_path.is_dir():
        print(f"❌ Error: Folder '{clean_path}' not found.")
        return

    double_encrypt = config.get('double_encryption_on_archive', 'no').lower() == 'yes'
    temp_dir, source_to_archive = None, clean_path
    
    try:
        if double_encrypt:
            print("Double encryption enabled. Creating a temporary encrypted copy of the folder...")
            temp_dir = Path(tempfile.mkdtemp())
            temp_source_path = temp_dir / clean_path.name
            shutil.copytree(clean_path, temp_source_path)
            process_folder_in_place(temp_source_path, password, 'encrypt', config)
            source_to_archive = temp_source_path
            print("Temporary copy encrypted.")
        
        archive_base_name = clean_path.name or 'archive'
        if archive_contents_only:
            archive_file = Path(shutil.make_archive(archive_base_name, 'zip', root_dir=source_to_archive))
        else:
            archive_file = Path(shutil.make_archive(archive_base_name, 'zip', root_dir=source_to_archive.parent, base_dir=source_to_archive.name))
        
        print(f"Temporary archive '{archive_file.name}' created.")
        process_single_file(archive_file, password, 'encrypt', config)

        if confirm_deletion(clean_path, config):
            try:
                print(f"Deleting original folder '{clean_path}'...")
                shutil.rmtree(clean_path)
                print("✅ Original folder has been deleted.")
            except PermissionError:
                print(f"❌ Deletion failed: Access to '{clean_path}' was denied.")
            except Exception as e:
                print(f"❌ An unexpected error occurred during deletion: {e}")
        else:
            print("ℹ️ Original folder was kept.")
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir)
            print("Temporary directory cleaned up.")

def encrypt_text(text: str, password: str, config: dict) -> str:
    """Encrypts a text string."""
    encrypted_bytes = encrypt_data(text.encode('utf-8'), "", password, config)
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

def decrypt_text(encrypted_text: str, password: str, config: dict) -> str:
    """Decrypts a text string."""
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
        decrypted_data, _ = decrypt_data(encrypted_bytes, password, config)
        return decrypted_data.decode('utf-8')
    except Exception:
        return "❌ Decryption failed."

# --- UI & Helper Functions ---

def get_password(config: dict, confirm: bool = True, prompt_message: str = "Please enter your password: ") -> Optional[str]:
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
                continue # Ask for password again

        if confirm:
            password_confirm = getpass.getpass("Confirm your password: ")
            if password != password_confirm:
                print("❌ The passwords do not match.")
                # We don't return here, allowing the user to retry entering the password
            else:
                return password # Success
        else:
            return password # Success, no confirmation needed

def confirm_deletion(folder_path: Path, config: dict) -> bool:
    """Asks the user for confirmation to delete the original folder, showing the default."""
    default = config.get('default_delete_confirmation', 'no').lower()
    
    # GEÄNDERT: Fügt [DEFAULT] zur Standard-Option hinzu
    if default == 'yes':
        prompt = f"Delete original folder '{folder_path}'? [Y[DEFAULT]/n]: "
    else:
        prompt = f"Delete original folder '{folder_path}'? [y/N[DEFAULT]]: "
    
    answer = input(prompt).lower().strip()
    
    if answer == '':
        return default == 'yes'
    
    return answer in ['y', 'yes']

# --- Menu Handlers ---

def handle_file_menu(config: dict) -> None:
    """Handles the user menu for file-related operations."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear');
        print("--- Category: Files ---")
        print("  [1] Encrypt single file")
        print("  [2] Decrypt single file")
        print("  [3] Encrypt files by pattern (e.g., docs/*)")
        print("  [9] Back to main menu")
        choice = input("> ")

        if choice == '1':
            path = Path(input("Path to file: "))
            if path.is_file():
                if pwd := get_password(config):
                    process_single_file(path, pwd, 'encrypt', config)
            else:
                print("❌ Invalid file path.")
        elif choice == '2':
            path = Path(input("Path to encrypted file: "))
            if path.is_file():
                if pwd := get_password(config, confirm=False):
                    process_single_file(path, pwd, 'decrypt', config)
            else:
                print("❌ Invalid file path.")
        elif choice == '3':
            pattern = input("Enter path pattern (e.g., 'data/*.txt' or 'project/**/*'): ")
            try:
                files_to_process = [Path(p) for p in glob.glob(pattern, recursive=True) if os.path.isfile(p)]
                if not files_to_process:
                    print(f"No files found matching the pattern '{pattern}'.")
                else:
                    print(f"\nFound {len(files_to_process)} file(s) to encrypt:")
                    for p in files_to_process:
                        print(f"  - {p}")
                    if input("\nDo you want to encrypt all these files? [y/N]: ").lower() in ['y', 'yes']:
                        if pwd := get_password(config):
                            for file_path in files_to_process:
                                process_single_file(file_path, pwd, 'encrypt', config)
                    else:
                        print("Operation cancelled.")
            except Exception as e:
                print(f"❌ An error occurred with the pattern: {e}")
        elif choice == '9':
            break
        else:
            print("Invalid selection.")
        input("\nPress Enter to continue...")

def handle_folder_menu(config: dict) -> None:
    """Handles the user menu for folder-related operations."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("--- Category: Folders ---")
        print("  [1] Encrypt folder (in-place)")
        print("  [2] Decrypt folder (in-place)")
        print("  [3] Encrypt folder as archive")
        print("  [4] Decrypt and unpack standard archive")
        print("  [5] Decrypt and unpack DOUBLE-ENCRYPTED(config) archive")
        print("  [9] Back to main menu")
        choice = input("> ")

        if choice in ['1', '2']:
            action = 'encrypt' if choice == '1' else 'decrypt'
            path = Path(input("Path to folder: "))
            if path.is_dir():
                if pwd := get_password(config, confirm=(action == 'encrypt')):
                    process_folder_in_place(path, pwd, action, config)
            else:
                print("❌ Invalid folder path.")
        elif choice == '3':
            path_str = input("Path to folder (e.g., 'docs' or 'docs/*'): ")
            if pwd := get_password(config):
                create_and_encrypt_archive(path_str, pwd, config)
        elif choice == '4':
            path = Path(input("Path to encrypted archive: "))
            if path.is_file():
                if pwd := get_password(config, confirm=False):
                    process_single_file(path, pwd, 'decrypt', config, unpack=True)
            else:
                print("❌ Invalid file path.")
        elif choice == '5':
            path = Path(input("Path to double-encrypted archive: "))
            if path.is_file():
                print("\n--- Step 1: Decrypting the outer archive ---")
                outer_pwd = get_password(config, confirm=False, prompt_message="Enter password for the ARCHIVE file: ")
                if outer_pwd:
                    unpacked_folder_path = process_single_file(path, outer_pwd, 'decrypt', config, unpack=True)
                    if unpacked_folder_path and unpacked_folder_path.is_dir():
                        print("\n--- Step 2: Decrypting inner files ---")
                        inner_pwd = get_password(config, confirm=False, prompt_message=f"Enter password for files INSIDE '{unpacked_folder_path.name}': ")
                        if inner_pwd:
                            process_folder_in_place(unpacked_folder_path, inner_pwd, 'decrypt', config)
                        else:
                            print("Operation aborted. Folder is unpacked but its content remains encrypted.")
            else:
                print("❌ Invalid file path.")
        elif choice == '9':
            break
        else:
            print("Invalid selection.")
        input("\nPress Enter to continue...")

def handle_text_menu(config: dict) -> None:
    """Handles the user menu for text message operations."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("--- Category: Text Messages ---")
        print("  [1] Encrypt text message\n  [2] Decrypt text message\n  [9] Back to main menu")
        choice = input("> ")
        if choice == '1':
            text = input("Enter the text:\n> ")
            if pwd := get_password(config):
                print(f"\nYOUR ENCRYPTED MESSAGE:\n{encrypt_text(text, pwd, config)}")
        elif choice == '2':
            text = input("Paste the encrypted message:\n> ")
            if pwd := get_password(config, confirm=False):
                print(f"\nYOUR DECRYPTED MESSAGE:\n{decrypt_text(text, pwd, config)}")
        elif choice == '9':
            break
        input("\nPress Enter to continue...")

def handle_config_menu() -> None:
    """Displays the configuration and offers to open it in an editor."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("--- Current Configuration (config.ini) ---")
    config_path = Path('config.ini')
    try:
        print(config_path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        print("❌ 'config.ini' not found.")
        input("\nPress Enter to continue...")
        return
    print("-" * 45)
    if input("Press 'e' to edit, or any other key to return: ").lower() == 'e':
        editor = None
        if sys.platform == "win32":
            editor = "notepad"
        elif sys.platform == "darwin":
            editor = "open -t" # macOS default text editor
        else: # Linux
            editor = os.environ.get('EDITOR') or (shutil.which('nano') or shutil.which('vi'))
        
        if editor:
            print(f"Attempting to open '{config_path}' with '{editor}'...")
            try:
                os.system(f"{editor} {config_path}")
                print("Config editor closed.")
            except Exception as e:
                print(f"❌ Could not open editor: {e}")
        else:
            print("❌ Could not find a suitable text editor.")
        input("\nPress Enter to continue...")

def handle_debug_menu() -> None:
    """Handles the menu for analysis and debug tools."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("--- Category: Debug/Analysis Tools ---")
        print("  [1] Read metadata from encrypted file (Salt, etc.)")
        print("  [2] Verify file checksum (SHA256/512)")
        print("  [9] Back to main menu")
        choice = input("> ")

        if choice == '1':
            path = Path(input("Path to encrypted file: "))
            read_file_metadata(path)
        elif choice == '2':
            path = Path(input("Path to file to verify: "))
            if not path.is_file():
                print("❌ Invalid file path.")
            else:
                algo_choice = input("Select algorithm [1] SHA-256 (default), [2] SHA-512: ")
                algorithm = 'sha512' if algo_choice == '2' else 'sha256'
                
                expected_hash = input(f"Paste the expected {algorithm.upper()} hash: ").lower().strip()
                if not expected_hash:
                    print("❌ No hash provided.")
                else:
                    print(f"Calculating {algorithm.upper()} hash for '{path.name}'...")
                    if calculated_hash := calculate_hash(path, algorithm):
                        print(f"  > Calculated: {calculated_hash}\n  > Expected:   {expected_hash}")
                        if calculated_hash == expected_hash:
                            print("\n✅ Match! The file is not corrupted.")
                        else:
                            print("\n❌ MISMATCH! The file may be corrupted or has been altered.")
        elif choice == '9':
            break
        else:
            print("Invalid selection.")
        input("\nPress Enter to continue...")

def read_file_metadata(file_path: Path) -> None:
    """Reads and displays metadata (salt size, salt) from an encrypted file."""
    if not file_path.is_file():
        print(f"❌ Error: File not found at '{file_path}'")
        return
    try:
        with file_path.open('rb') as f:
            salt_size_byte = f.read(1)
            if not salt_size_byte:
                print("❌ Error: File is empty.")
                return
            
            salt_size = int.from_bytes(salt_size_byte, 'big')
            salt = f.read(salt_size)
            if len(salt) < salt_size:
                print("❌ Error: File is corrupt or too short to contain the full salt.")
                return

            print("\n--- File Metadata Analysis ---")
            print(f"  File: {file_path.name}")
            print(f"  Total Size: {file_path.stat().st_size} bytes")
            print("-" * 20)
            print(f"  Detected Salt Size: {salt_size} bytes")
            print(f"  Salt (hex): {salt.hex()}")
            print("------------------------------")
    except Exception as e:
        print(f"❌ An unexpected error occurred while reading the file: {e}")

def main() -> None:
    """Main function to run the application's menu loop."""
    while True:
        try:
            config_path = Path('config.ini')
            if not config_path.exists():
                print("Error: 'config.ini' not found. Please create the file.")
                return
            config = configparser.ConfigParser()
            config.read(config_path)
            settings = config['Settings']
        except Exception as e:
            print(f"Error loading config.ini: {e}")
            return

        os.system('cls' if os.name == 'nt' else 'clear')
        print("🔒 Python Encryption Tool - MAIN MENU 🔒")
        print("=" * 45)
        print("  [1] Category: Files")
        print("  [2] Category: Folders")
        print("  [3] Category: Text Messages")
        print("  [7] View/Edit Config")
        print("  [8] Debug/Analysis Tools")
        print("  [9] Exit Program")
        print("-" * 45)
        choice = input("Select a category: ")

        if choice == '1':
            handle_file_menu(settings)
        elif choice == '2':
            handle_folder_menu(settings)
        elif choice == '3':
            handle_text_menu(settings)
        elif choice == '7':
            handle_config_menu()
        elif choice == '8':
            handle_debug_menu()
        elif choice == '9':
            print("Goodbye! 👋")
            break
        else:
            print("Invalid selection.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user. 👋")
        sys.exit(0)
    except Exception as e:
        # A final catch-all for any unexpected critical errors
        print(f"\n\nAn unexpected critical error occurred: {e}")
        sys.exit(1)
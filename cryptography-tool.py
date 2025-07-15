import os
import base64
import configparser
import getpass
import glob
import hashlib
import shutil
import sys
import tempfile
import time
import multiprocessing
import zipfile
from pathlib import Path
from typing import Optional, Tuple, Any, Dict, List

# --- Optional Dependencies ---
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    class tqdm:
        def __init__(self, *args: Any, **kwargs: Any):
            self.iterable = args[0] if args else None
            self.total = kwargs.get('total', None)
            if desc := kwargs.get('desc'): print(f"{desc}...")
        def __iter__(self) -> Any: return iter(self.iterable)
        def __enter__(self) -> 'tqdm': return self
        def __exit__(self, *args: Any, **kwargs: Any) -> None:
            if self.iterable: print("Operation finished.")
        def update(self, n: int = 1) -> None: pass
        def set_postfix_str(self, s: str) -> None: pass
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# --- Required Dependencies ---
try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Error: 'zxcvbn' library not found. Please install it using: pip install zxcvbn-python")
    sys.exit(1)
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Constants ---
CHUNK_SIZE_KB_DEFAULT = 4096

# --- Helper Functions ---
def format_duration(seconds: float) -> str:
    """Formats a duration in seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes, seconds = divmod(seconds, 60)
    return f"{int(minutes)} minute(s) and {seconds:.2f} seconds"

# --- Cryptography and Hash Logic ---
def derive_key(password: str, salt: bytes, config: Dict, key_length: int = 32) -> bytes:
    iterations = int(config.get('pbkdf2_iterations', 600000))
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(password.encode())
def calculate_hash(file_path: Path, config: Dict, algorithm: str = 'sha256') -> Optional[str]:
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    chunk_size = int(config.get('chunk_size_kb', CHUNK_SIZE_KB_DEFAULT)) * 1024
    use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
    hasher = hashlib.new(algorithm)
    last_update_time = 0
    try:
        with file_path.open('rb') as f, tqdm(total=file_path.stat().st_size, unit='B', unit_scale=True, desc=f"Hashing {file_path.name}", leave=False, ascii=use_ascii) as pbar:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
                pbar.update(len(chunk))
                if is_debug and PSUTIL_AVAILABLE and (time.time() - last_update_time > 0.5):
                    pbar.set_postfix_str(f"CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%")
                    last_update_time = time.time()
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error calculating hash: {e}")
        return None
def encrypt_text_data(data: bytes, password: str, config: Dict) -> bytes:
    salt_size = int(config.get('salt_size_bytes', 16))
    salt = os.urandom(salt_size)
    key = derive_key(password, salt, config)
    fernet = Fernet(base64.urlsafe_b64encode(key))
    return salt_size.to_bytes(1, 'big') + salt + fernet.encrypt(data)
def decrypt_text_data(encrypted_blob: bytes, password: str, config: Dict) -> bytes:
    try:
        salt_size = int.from_bytes(encrypted_blob[0:1], 'big')
        salt, token = encrypted_blob[1:1+salt_size], encrypted_blob[1+salt_size:]
        key = derive_key(password, salt, config)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        return fernet.decrypt(token)
    except (InvalidToken, TypeError, IndexError, ValueError):
        raise ValueError("Decryption failed. Wrong password or corrupt data.")

# --- Streaming Encryption (for files) ---
def encrypt_file_stream(source_path: Path, password: str, config: Dict) -> Optional[Path]:
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    chunk_size = int(config.get('chunk_size_kb', CHUNK_SIZE_KB_DEFAULT)) * 1024
    use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
    encrypted_file_path = source_path.with_suffix(config['encrypted_file_extension'])
    last_update_time = 0
    try:
        salt_size = int(config.get('salt_size_bytes', 16))
        salt = os.urandom(salt_size)
        key = derive_key(password, salt, config)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        ext_bytes = source_path.suffix.encode('utf-8')
        with source_path.open('rb') as f_in, encrypted_file_path.open('wb') as f_out:
            f_out.write(salt_size.to_bytes(1, 'big')); f_out.write(salt)
            f_out.write(len(ext_bytes).to_bytes(1, 'big')); f_out.write(ext_bytes)
            with tqdm(total=source_path.stat().st_size, unit='B', unit_scale=True, desc=f"Encrypting {source_path.name}", leave=False, ascii=use_ascii) as pbar:
                while chunk := f_in.read(chunk_size):
                    encrypted_chunk = fernet.encrypt(chunk)
                    f_out.write(len(encrypted_chunk).to_bytes(4, 'big'))
                    f_out.write(encrypted_chunk)
                    pbar.update(len(chunk))
                    if is_debug and PSUTIL_AVAILABLE and (time.time() - last_update_time > 0.5):
                        pbar.set_postfix_str(f"CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%")
                        last_update_time = time.time()
        source_path.unlink()
        return encrypted_file_path
    except Exception as e:
        print(f"❌ Encryption failed for {source_path.name}: {e}")
        if encrypted_file_path.exists(): encrypted_file_path.unlink()
        return None
def decrypt_file_stream(source_path: Path, password: str, config: Dict) -> Optional[Path]:
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
    original_file_path = None; last_update_time = 0
    try:
        with source_path.open('rb') as f_in:
            salt_size = int.from_bytes(f_in.read(1), 'big'); salt = f_in.read(salt_size)
            ext_len = int.from_bytes(f_in.read(1), 'big'); original_ext = f_in.read(ext_len).decode('utf-8')
            key = derive_key(password, salt, config)
            fernet = Fernet(base64.urlsafe_b64encode(key))
            original_file_path = source_path.with_suffix(original_ext)
            with original_file_path.open('wb') as f_out:
                with tqdm(total=source_path.stat().st_size, unit='B', unit_scale=True, desc=f"Decrypting {source_path.name}", leave=False, ascii=use_ascii) as pbar:
                    pbar.update(1 + salt_size + 1 + ext_len)
                    while chunk_len_bytes := f_in.read(4):
                        chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                        encrypted_chunk = f_in.read(chunk_len)
                        decrypted_chunk = fernet.decrypt(encrypted_chunk, ttl=None)
                        f_out.write(decrypted_chunk)
                        pbar.update(4 + chunk_len)
                        if is_debug and PSUTIL_AVAILABLE and (time.time() - last_update_time > 0.5):
                            pbar.set_postfix_str(f"CPU: {psutil.cpu_percent()}% | RAM: {psutil.virtual_memory().percent}%")
                            last_update_time = time.time()
        source_path.unlink()
        return original_file_path
    except (InvalidToken, ValueError):
        print(f"❌ Decryption failed for {source_path.name}. Wrong password or corrupt file.")
        if original_file_path and original_file_path.exists(): original_file_path.unlink()
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred with {source_path.name}: {e}")
        if original_file_path and original_file_path.exists(): original_file_path.unlink()
        return None

# --- High-Level Processing Functions ---
def worker_process_single_file(args: Tuple[str, str, str, Dict, bool]) -> None:
    file_path_str, password, action, config, unpack = args
    file_path = Path(file_path_str)
    sys.stdout.write(f"Processing: {file_path.name}\n"); sys.stdout.flush()
    process_single_file_main_thread(file_path, password, action, config, unpack)
def process_single_file_main_thread(file_path: Path, password: str, action: str, config: Dict, unpack: bool = False) -> Optional[Path]:
    if action == 'encrypt':
        encrypted_path = encrypt_file_stream(file_path, password, config)
        if encrypted_path:
            print(f"✅ Encrypted successfully: {encrypted_path.name}")
            if checksum := calculate_hash(encrypted_path, config):
                print(f"   └── SHA-256 Checksum: {checksum}")
            return encrypted_path
    elif action == 'decrypt':
        decrypted_path = decrypt_file_stream(file_path, password, config)
        if decrypted_path:
            if unpack and decrypted_path.suffix == '.zip':
                print(f"✅ Archive decrypted. Unpacking '{decrypted_path.name}'...")
                extract_dir = decrypted_path.parent
                use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
                try:
                    with zipfile.ZipFile(decrypted_path, 'r') as zipf:
                        file_list = zipf.infolist()
                        total_size = sum(file.file_size for file in file_list)
                        with tqdm(total=total_size, unit='B', unit_scale=True, desc="Unpacking archive", leave=False, ascii=use_ascii) as pbar:
                            for file in file_list:
                                pbar.set_description(f"Unpacking {Path(file.filename).name}")
                                zipf.extract(member=file, path=extract_dir)
                                pbar.update(file.file_size)
                    print("\n✅ Unpacking complete.")
                    return extract_dir / decrypted_path.stem
                except Exception as e:
                    print(f"❌ Failed to unpack archive: {e}")
                finally:
                    if decrypted_path.exists(): decrypted_path.unlink()
            else:
                print(f"✅ Decrypted successfully: {decrypted_path.name}")
                return decrypted_path
    return None
def batch_process_files(files_to_process: List[Path], password: str, action: str, config: Dict) -> None:
    start_time = time.time()
    use_multiprocessing = config.get('enable_multiprocessing', 'no').lower() == 'yes'
    use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
    if use_multiprocessing and TQDM_AVAILABLE:
        total_cores = os.cpu_count() or 1
        worker_count_config = int(config.get('worker_processes', 0))
        workers = total_cores if worker_count_config == 0 else min(worker_count_config, total_cores)
        if config.get('debug_mode', 'no').lower() == 'yes' and PSUTIL_AVAILABLE:
             print(f"DEBUG INFO: Multiprocessing enabled. System has {total_cores} cores. Configured to use {workers}.")
        tasks = [(str(f), password, action, config, False) for f in files_to_process]
        try:
            with multiprocessing.Pool(processes=workers) as pool, tqdm(total=len(tasks), desc=f"{action.capitalize()}ing batch", ascii=use_ascii) as pbar:
                for _ in pool.imap_unordered(worker_process_single_file, tasks):
                    pbar.update(1)
        except Exception as e:
            print(f"An error occurred during multiprocessing: {e}")
    else:
        if use_multiprocessing and not TQDM_AVAILABLE:
            print("INFO: Multiprocessing requires 'tqdm' for progress tracking. Falling back to sequential processing.")
        print("INFO: Processing files sequentially.")
        for item in files_to_process:
            print("-" * 20)
            process_single_file_main_thread(item, password, action, config, False)
    duration = time.time() - start_time
    print(f"\n✅ Batch operation finished in {format_duration(duration)}.")
def process_folder_in_place(path: Path, password: str, action: str, config: Dict) -> None:
    print("-" * 30); print(f"{action.capitalize()}ing all files in folder '{path}'...")
    extension = config['encrypted_file_extension']
    files_to_process = [item for item in path.rglob('*') if item.is_file() and ((action == 'encrypt' and item.suffix != extension) or (action == 'decrypt' and item.suffix == extension))]
    if not files_to_process:
        print("No files to process."); return
    batch_process_files(files_to_process, password, action, config)
def create_and_encrypt_archive(path_str: str, password: str, config: Dict) -> None:
    start_time = time.time()
    print("Initializing archive creation. This may take a while for large folders...")
    path_str, archive_contents_only = path_str.strip(), False
    clean_path_str = path_str
    if path_str.endswith(('/*','\\*')):
        clean_path_str, archive_contents_only = path_str[:-2], True
    elif path_str.endswith(('/', '\\')):
        clean_path_str, archive_contents_only = path_str[:-1], True
    clean_path = Path(clean_path_str)
    if not clean_path.is_dir():
        print(f"❌ Error: Folder '{clean_path}' not found."); return
    double_encrypt = config.get('double_encryption_on_archive', 'no').lower() == 'yes'
    temp_dir, source_to_archive = None, clean_path
    try:
        if double_encrypt:
            print("Double encryption enabled. Creating a temporary encrypted copy...")
            temp_dir = Path(tempfile.mkdtemp())
            temp_source_path = temp_dir / clean_path.name
            shutil.copytree(clean_path, temp_source_path)
            process_folder_in_place(temp_source_path, password, 'encrypt', config)
            source_to_archive = temp_source_path
            print("Temporary copy encrypted.")
        archive_base_name = clean_path.name or 'archive'
        archive_file = Path(f"{archive_base_name}.zip")
        files_to_add = [f for f in source_to_archive.rglob("*") if f.is_file()]
        total_size = sum(f.stat().st_size for f in files_to_add)
        use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
        with zipfile.ZipFile(archive_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Creating archive", leave=False, ascii=use_ascii) as pbar:
                for file in files_to_add:
                    pbar.set_description(f"Archiving {file.name}")
                    if archive_contents_only:
                        arcname = file.relative_to(source_to_archive)
                    else:
                        arcname = file.relative_to(source_to_archive.parent)
                    zipf.write(file, arcname)
                    pbar.update(file.stat().st_size)
        print(f"\nTemporary archive '{archive_file.name}' created.")
        process_single_file_main_thread(archive_file, password, 'encrypt', config, False)
        if confirm_deletion(clean_path, config):
            try:
                print(f"Deleting original folder '{clean_path}'...")
                shutil.rmtree(clean_path)
                print("✅ Original folder has been deleted.")
            except PermissionError: print(f"❌ Deletion failed: Access to '{clean_path}' was denied.")
            except Exception as e: print(f"❌ An unexpected error occurred during deletion: {e}")
        else: print("ℹ️ Original folder was kept.")
    finally:
        if temp_dir and temp_dir.exists(): shutil.rmtree(temp_dir); print("Temporary directory cleaned up.")
    duration = time.time() - start_time
    print(f"\n✅ Archive creation and encryption finished in {format_duration(duration)}.")
def encrypt_text(text: str, password: str, config: Dict) -> str:
    encrypted_bytes = encrypt_text_data(text.encode('utf-8'), password, config)
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
def decrypt_text(encrypted_text: str, password: str, config: Dict) -> str:
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
        decrypted_data = decrypt_text_data(encrypted_bytes, password, config)
        return decrypted_data.decode('utf-8')
    except Exception: return "❌ Decryption failed."

# --- UI & Helper Functions ---
def get_password(config: Dict, confirm: bool = True, prompt_message: str = "Please enter your password: ") -> Optional[str]:
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    if is_debug and confirm:
        print("\n-- WARNING: DEBUG MODE IS ON. Password strength check is disabled. --")
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
    return (answer == '' and default == 'yes') or answer in ['y', 'yes']
def get_title_suffix(config: Dict) -> str:
    if config.get('debug_mode', 'no').lower() == 'yes':
        return " [DEBUG]"
    return ""

# --- Menu Handlers ---
def handle_file_menu(config: Dict) -> None:
    title_suffix = get_title_suffix(config)
    while True:
        os.system('cls' if os.name == 'nt' else 'clear'); print(f"--- Category: Files ---{title_suffix}")
        print("  [1] Encrypt single file\n  [2] Decrypt single file\n  [3] Encrypt files by pattern\n  [9] Back to main menu")
        choice = input("> ")
        if choice == '1':
            path = Path(input("Path to file: "))
            if path.is_file():
                if pwd := get_password(config):
                    start_time = time.time()
                    process_single_file_main_thread(path, pwd, 'encrypt', config)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '2':
            path = Path(input("Path to encrypted file: "))
            if path.is_file():
                if pwd := get_password(config, confirm=False):
                    start_time = time.time()
                    process_single_file_main_thread(path, pwd, 'decrypt', config)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '3':
            pattern = input("Enter path pattern (e.g., 'data/*.txt' or 'project/**/*'): ")
            try:
                files_to_process = [Path(p) for p in glob.glob(pattern, recursive=True) if os.path.isfile(p)]
                if not files_to_process:
                    print(f"No files found for pattern '{pattern}'.")
                else:
                    print(f"\nFound {len(files_to_process)} file(s) to encrypt:")
                    for p in files_to_process: print(f"  - {p}")
                    if input("\nDo you want to encrypt all these files? [y/N]: ").lower() in ['y', 'yes']:
                        if pwd := get_password(config):
                            batch_process_files(files_to_process, pwd, 'encrypt', config)
                    else: print("Operation cancelled.")
            except Exception as e: print(f"❌ An error occurred: {e}")
        elif choice == '9': break
        input("\nPress Enter to continue...")
def handle_folder_menu(config: Dict) -> None:
    title_suffix = get_title_suffix(config)
    while True:
        os.system('cls'if os.name == 'nt' else 'clear');print(f"--- Category: Folders ---{title_suffix}")
        print("  [1] Encrypt folder (in-place)\n  [2] Decrypt folder (in-place)\n  [3] Encrypt folder as archive\n  [4] Decrypt and unpack standard archive\n  [5] Decrypt and unpack DOUBLE-ENCRYPTED(config) archive\n  [9] Back to main menu")
        choice = input("> ")
        if choice in ['1', '2']:
            action='encrypt'if choice == '1' else'decrypt'
            path = Path(input("Path to folder: "))
            if path.is_dir():
                if pwd := get_password(config, confirm=(action=='encrypt')): process_folder_in_place(path, pwd, action, config)
            else: print("❌ Invalid folder path.")
        elif choice == '3':
            path_str = input("Path to folder (e.g., 'docs' or 'docs/*'): ")
            if pwd := get_password(config): create_and_encrypt_archive(path_str, pwd, config)
        elif choice == '4':
            path = Path(input("Path to encrypted archive: "))
            if path.is_file():
                if pwd := get_password(config, confirm=False):
                    start_time = time.time()
                    process_single_file_main_thread(path, pwd, 'decrypt', config, unpack=True)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '5':
            path = Path(input("Path to double-encrypted archive: "))
            if path.is_file():
                start_time = time.time()
                print("\n--- Step 1: Decrypting the outer archive ---")
                outer_pwd = get_password(config, confirm=False, prompt_message="Enter password for the ARCHIVE file: ")
                if outer_pwd:
                    unpacked_folder_path = process_single_file_main_thread(path, outer_pwd, 'decrypt', config, unpack=True)
                    if unpacked_folder_path and unpacked_folder_path.is_dir():
                        print("\n--- Step 2: Decrypting inner files ---")
                        inner_pwd = get_password(config, confirm=False, prompt_message=f"Enter password for files INSIDE '{unpacked_folder_path.name}': ")
                        if inner_pwd:
                            process_folder_in_place(unpacked_folder_path, inner_pwd, 'decrypt', config)
                        else: print("Operation aborted. Folder is unpacked but its content remains encrypted.")
                duration = time.time() - start_time
                print(f"\n✅ Operation finished in {format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '9': break
        else: print("Invalid selection.")
        input("\nPress Enter to continue...")
def handle_text_menu(config: Dict) -> None:
    title_suffix = get_title_suffix(config)
    while True:
        os.system('cls'if os.name == 'nt' else 'clear'); print(f"--- Category: Text Messages ---{title_suffix}")
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
        elif choice == '9': break
        input("\nPress Enter to continue...")
def handle_config_menu(config: Dict) -> None:
    title_suffix = get_title_suffix(config)
    os.system('cls'if os.name == 'nt' else 'clear');print(f"--- Current Configuration (config.ini) ---{title_suffix}")
    config_path = Path('config.ini')
    try:
        print(config_path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        print("❌ 'config.ini' not found.");input("\nPress Enter...");return
    print("-" * 45)
    if input("Press 'e' to edit, or any other key to return: ").lower() == 'e':
        editor = None
        if sys.platform == "win32": editor = "notepad"
        elif sys.platform == "darwin": editor = "open -t"
        else: editor = os.environ.get('EDITOR') or (shutil.which('nano') or shutil.which('vi'))
        if editor:
            print(f"Attempting to open '{config_path}' with '{editor}'...")
            try:
                os.system(f'"{editor}" "{config_path}"')
                print("Config editor closed.")
            except Exception as e: print(f"❌ Could not open editor: {e}")
        else: print("❌ Could not find a suitable text editor.")
        input("\nPress Enter to continue...")
def handle_debug_menu(config: Dict) -> None:
    title_suffix = get_title_suffix(config)
    while True:
        os.system('cls'if os.name == 'nt' else 'clear');
        print(f"--- Category: Debug/Analysis Tools ---{title_suffix}")
        print("  [1] Read metadata from encrypted file\n  [2] Verify file checksum (SHA256/512)\n  [9] Back to main menu")
        choice = input("> ")
        if choice == '1':
            path = Path(input("Path to encrypted file: "))
            read_file_metadata(path)
        elif choice == '2':
            path = Path(input("Path to file to verify: "))
            if not path.is_file(): print("❌ Invalid file path.")
            else:
                algo_choice = input("Select algorithm [1] SHA-256 (default), [2] SHA-512: ")
                algorithm = 'sha512' if algo_choice == '2' else 'sha256'
                expected_hash = input(f"Paste the expected {algorithm.upper()} hash: ").lower().strip()
                if not expected_hash: print("❌ No hash provided.")
                else:
                    print(f"Calculating {algorithm.upper()} hash for '{path.name}'...")
                    if calculated_hash := calculate_hash(path, config, algorithm):
                        print(f"  > Calculated: {calculated_hash}\n  > Expected:   {expected_hash}")
                        if calculated_hash == expected_hash: print("\n✅ Match! The file is not corrupted.")
                        else: print("\n❌ MISMATCH! The file may be corrupted or has been altered.")
        elif choice == '9': break
        else: print("Invalid selection.")
        input("\nPress Enter to continue...")
def read_file_metadata(file_path: Path) -> None:
    if not file_path.is_file():
        print(f"❌ Error: File not found at '{file_path}'"); return
    try:
        with file_path.open('rb') as f:
            salt_size_byte = f.read(1)
            if not salt_size_byte: print("❌ Error: File is empty."); return
            salt_size = int.from_bytes(salt_size_byte, 'big')
            salt = f.read(salt_size)
            if len(salt) < salt_size: print("❌ Error: File is corrupt or too short to contain the full salt."); return
            print("\n--- File Metadata Analysis ---")
            print(f"  File: {file_path.name}\n  Total Size: {file_path.stat().st_size} bytes")
            print("-" * 20)
            print(f"  Detected Salt Size: {salt_size} bytes\n  Salt (hex): {salt.hex()}")
            print("------------------------------")
    except Exception as e: print(f"❌ An unexpected error occurred while reading the file: {e}")

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
                print("Error: 'config.ini' not found. Please create the file."); return
            config = configparser.ConfigParser(interpolation=None); config.read(config_path)
            settings: Dict[str, Any] = {}
            for section in config.sections():
                settings.update(dict(config.items(section)))
        except Exception as e: print(f"Error loading config.ini: {e}"); return
        
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
    multiprocessing.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user. 👋"); sys.exit(0)
    except Exception as e:
        print(f"\n\nAn unexpected critical error occurred: {e}")
        sys.exit(1)
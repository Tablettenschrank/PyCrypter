import base64
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional, Tuple, Dict, List

# Import from our own modules
from .crypto import (
    encrypt_file_stream,
    decrypt_file_stream,
    calculate_hash,
    encrypt_text_data,
    decrypt_text_data
)
# GEÄNDERT: 'check_disk_space' wurde aus den Imports entfernt
from .utils import confirm_deletion, format_duration

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

# --- High-Level Processing Functions ---
def worker_process_single_file(args: Tuple[str, str, str, Dict, bool]) -> None:
    """Wrapper function for multiprocessing pool. Handles one file."""
    file_path_str, password, action, config, unpack = args
    file_path = Path(file_path_str)
    sys.stdout.write(f"Processing: {file_path.name}\n"); sys.stdout.flush()
    process_single_file_main_thread(file_path, password, action, config, unpack)

def process_single_file_main_thread(file_path: Path, password: str, action: str, config: Dict, unpack: bool = False) -> Optional[Path]:
    """Orchestrates single-threaded streaming en/decryption for a single file."""
    if action == 'encrypt':
        # GEÄNDERT: Die Speicherplatz-Prüfung wurde entfernt.
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
    """Handles batch processing of files, either sequentially or in parallel."""
    start_time = time.time()
    # GEÄNDERT: Die Speicherplatz-Prüfung wurde entfernt.
    use_multiprocessing = config.get('enable_multiprocessing', 'no').lower() == 'yes'
    if use_multiprocessing and TQDM_AVAILABLE:
        total_cores = os.cpu_count() or 1
        worker_count_config = int(config.get('worker_processes', 0))
        workers = total_cores if worker_count_config == 0 else min(worker_count_config, total_cores)
        if config.get('debug_mode', 'no').lower() == 'yes' and PSUTIL_AVAILABLE:
             print(f"DEBUG INFO: Multiprocessing enabled. System has {total_cores} cores. Configured to use {workers}.")
        tasks = [(str(f), password, action, config, False) for f in files_to_process]
        try:
            with multiprocessing.Pool(processes=workers) as pool, tqdm(total=len(tasks), desc=f"{action.capitalize()}ing batch", ascii=(config.get('progress_bar_style') == 'ascii')) as pbar:
                for _ in pool.imap_unordered(worker_process_single_file, tasks):
                    pbar.update(1)
        except Exception as e:
            print(f"An error occurred during multiprocessing: {e}")
    else:
        if use_multiprocessing and not TQDM_AVAILABLE:
            print("INFO: Multiprocessing requires 'tqdm'. Falling back to sequential processing.")
        print("INFO: Processing files sequentially.")
        for item in files_to_process:
            print("-" * 20)
            process_single_file_main_thread(item, password, action, config, False)
    duration = time.time() - start_time
    print(f"\n✅ Batch operation finished in {format_duration(duration)}.")

def process_folder_in_place(path: Path, password: str, action: str, config: Dict) -> None:
    """Encrypts or decrypts all files within a folder."""
    print("-" * 30); print(f"{action.capitalize()}ing all files in folder '{path}'...")
    extension = config['encrypted_file_extension']
    files_to_process = [item for item in path.rglob('*') if item.is_file() and ((action == 'encrypt' and item.suffix != extension) or (action == 'decrypt' and item.suffix == extension))]
    if not files_to_process:
        print("No files to process."); return
    batch_process_files(files_to_process, password, action, config)

def create_and_encrypt_archive(path_str: str, password: str, config: Dict) -> None:
    """Creates an archive with a detailed byte-based progress bar and encrypts it."""
    start_time = time.time()
    path_str, archive_contents_only = path_str.strip(), False
    clean_path_str = path_str
    if path_str.endswith(('/*','\\*')):
        clean_path_str, archive_contents_only = path_str[:-2], True
    elif path_str.endswith(('/', '\\')):
        clean_path_str, archive_contents_only = path_str[:-1], True
    clean_path = Path(clean_path_str)
    if not clean_path.is_dir():
        print(f"❌ Error: Folder '{clean_path}' not found."); return
    print("Initializing archive creation. This may take a while for large folders...")
    # GEÄNDERT: Die Speicherplatz-Prüfung wurde entfernt.
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
                    arcname = file.relative_to(source_to_archive.parent) if not archive_contents_only else file.relative_to(source_to_archive)
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
import base64
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import zipfile
import random
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any

from . import crypto
from . import utils

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

# --- Constants ---
SPACE_BUFFER_MULTIPLIER = 1.05

# --- Helper for Test Suite ---
def remove_directory_robustly(dir_path: Path, max_retries: int = 3, delay: float = 1.0):
    """Tries to remove a directory, retrying on PermissionError."""
    for i in range(max_retries):
        try:
            shutil.rmtree(dir_path)
            print(f"✅ Test suite directory '{dir_path}' cleaned up.")
            return
        except OSError as e:
            print(f"Attempt {i+1}/{max_retries} to remove '{dir_path}' failed: {e}")
            if i < max_retries - 1:
                time.sleep(delay)
    print(f"❌ Failed to remove directory '{dir_path}' after {max_retries} attempts. Please remove it manually.")

# --- Test Suite Logic ---
def create_test_files(target_dir: Path, num_files: int, min_size: int, max_size: int, config: Dict) -> Optional[Dict[str, str]]:
    """Creates random files for the test suite and returns a hash dictionary."""
    original_hashes = {}
    file_sizes = [random.randint(min_size, max_size) for _ in range(num_files)]
    
    print(f"\nCreating {num_files} random test files...")
    for i, size in enumerate(file_sizes):
        file_path = target_dir / f"test_file_{i+1}.bin"
        print(f" -> Creating '{file_path.name}' with size {size/1024/1024:.2f} MB...")
        try:
            with file_path.open('wb') as f:
                chunk_size = 1024 * 1024
                for _ in range(size // chunk_size): f.write(os.urandom(chunk_size))
                f.write(os.urandom(size % chunk_size))
            original_hashes[str(file_path.name)] = crypto.calculate_hash(file_path, config, show_progress=False)
        except MemoryError:
            print(f"❌ Error creating test file '{file_path.name}': Not enough memory.")
            return None
        except Exception as e:
            print(f"❌ Error creating test file '{file_path.name}': {e}")
            return None
    return original_hashes

def verify_hashes(target_dir: Path, original_hashes: Dict, config: Dict) -> bool:
    """Verifies that files in a directory match the original hashes."""
    print(f"Verifying integrity of files in '{target_dir.name}'...")
    if not target_dir.is_dir():
        print(f"  [FAIL] Verification failed: Directory '{target_dir.name}' does not exist.")
        return False
    
    current_files = {f.name for f in target_dir.iterdir() if f.is_file()}
    original_files = set(original_hashes.keys())
    if current_files != original_files:
        print(f"  [FAIL] File list mismatch.")
        if missing := original_files - current_files: print(f"    Missing files: {missing}")
        if extra := current_files - original_files: print(f"    Extra files: {extra}")
        return False

    for original_name, original_hash in original_hashes.items():
        current_file_path = target_dir / original_name
        current_hash = crypto.calculate_hash(current_file_path, config, show_progress=False)
        if current_hash != original_hash:
            print(f"  [FAIL] Hash mismatch for '{original_name}'.")
            return False
    print("  [PASS] All file hashes match.")
    return True

def run_test_suite(config: Dict) -> None:
    """Orchestrates the entire automated test suite with interactive configuration."""
    print("\n--- Automated Test Suite ---")
    print("WARNING: This process will create large temporary files and can take a long time.")
    if not input("Do you want to proceed? [y/N]: ").lower() in ['y', 'yes']:
        print("Test suite aborted."); return

    while True:
        try:
            num_files_min_str = input("Enter minimum number of files [default: 3]: ") or "3"
            num_files_max_str = input("Enter maximum number of files [default: 5]: ") or "5"
            num_files_min = int(num_files_min_str)
            num_files_max = int(num_files_max_str)
            if num_files_min > num_files_max:
                print("❌ Error: Minimum count cannot be greater than maximum. Please try again.")
                continue
            break
        except ValueError:
            print("❌ Invalid number. Please enter integers only.")

    while True:
        min_size_str = input("Enter minimum file size (e.g., 1MB) [default: 1MB]: ") or "1MB"
        max_size_str = input("Enter maximum file size (e.g., 10MB) [default: 10MB]: ") or "10MB"
        min_size = utils.parse_size_string(min_size_str)
        max_size = utils.parse_size_string(max_size_str)
        if not all((min_size is not None, max_size is not None)):
            print("❌ Invalid size format. Use units like KB, MB, GB (e.g., '512kb', '50m', '1.5g').")
            continue
        if min_size > max_size:
            print("❌ Error: Minimum size cannot be greater than maximum. Please try again.")
            continue
        break

    num_files = random.randint(num_files_min, num_files_max)
    
    test_suite_dir = Path('./test_suite')
    if test_suite_dir.exists(): remove_directory_robustly(test_suite_dir)
    
    test_suite_dir.mkdir()
    original_data_dir = test_suite_dir / "original_data"
    original_data_dir.mkdir()
    password = "123"
    
    original_hashes = create_test_files(original_data_dir, num_files, min_size, max_size, config)
    if not original_hashes:
        print("❌ Test setup failed. Aborting."); remove_directory_robustly(test_suite_dir); return

    print("\n" + "="*40)
    print("--- Test 1: In-Place Encryption/Decryption ---")
    test_inplace_dir = test_suite_dir / "test_inplace"
    shutil.copytree(original_data_dir, test_inplace_dir)
    process_folder_in_place(test_inplace_dir, password, 'encrypt', config)
    process_folder_in_place(test_inplace_dir, password, 'decrypt', config)
    if verify_hashes(test_inplace_dir, original_hashes, config):
        print("✅ In-Place Test: PASSED")
    else:
        print("❌ In-Place Test: FAILED")
    print("="*40)

    print("\n" + "="*40)
    print("--- Test 2: Archive Encryption/Decryption ---")
    test_archive_dir = test_suite_dir / "test_archive"
    shutil.copytree(original_data_dir, test_archive_dir)
    create_and_encrypt_archive(str(test_archive_dir), password, config)
    
    archive_path = Path(f"{test_archive_dir.name}{config['encrypted_file_extension']}")
    
    if archive_path.exists():
        unpacked_path = process_single_file_main_thread(archive_path, password, 'decrypt', config, unpack=True)
        if unpacked_path and verify_hashes(unpacked_path, original_hashes, config):
            print("✅ Archive Test: PASSED")
        else:
            print("❌ Archive Test: FAILED")
    else:
        print(f"❌ Archive Test: FAILED - Encrypted archive '{archive_path}' not found.")
    print("="*40)

    print("\n--- Test Suite Finished ---")
    if input("Delete the 'test_suite' directory and all its contents? [Y/n]: ").lower() != 'n':
        remove_directory_robustly(test_suite_dir)

# --- High-Level Processing Functions ---
def worker_process_single_file(args: Tuple[str, str, str, Dict, bool]) -> Dict:
    file_path_str, password, action, config, unpack = args; file_path = Path(file_path_str)
    try:
        result_path = process_single_file_main_thread(file_path, password, action, config, unpack, show_progress=False)
        if result_path:
            checksum = crypto.calculate_hash(result_path, config, show_progress=False) if action == 'encrypt' else None
            return {'status': 'success', 'original': file_path_str, 'result': str(result_path), 'checksum': checksum}
    except Exception as e:
        return {'status': 'error', 'original': file_path_str, 'message': str(e)}
    return {'status': 'error', 'original': file_path_str, 'message': 'Processing failed without a specific error.'}

def process_single_file_main_thread(file_path: Path, password: str, action: str, config: Dict, unpack: bool = False, show_progress: bool = True) -> Optional[Path]:
    if action == 'encrypt':
        encrypted_path = crypto.encrypt_file_stream(file_path, password, config, show_progress=show_progress)
        if encrypted_path and show_progress:
            print(f"✅ Encrypted successfully: {encrypted_path.name}")
            if checksum := crypto.calculate_hash(encrypted_path, config):
                print(f"   └── SHA-256 Checksum: {checksum}")
        return encrypted_path
    elif action == 'decrypt':
        decrypted_path = crypto.decrypt_file_stream(file_path, password, config, show_progress=show_progress)
        if decrypted_path:
            if unpack and decrypted_path.suffix == '.zip':
                if show_progress: print(f"✅ Archive decrypted. Unpacking '{decrypted_path.name}'...")
                extract_dir = decrypted_path.parent
                use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
                try:
                    with zipfile.ZipFile(decrypted_path, 'r') as zipf:
                        file_list = zipf.infolist()
                        total_size = sum(file.file_size for file in file_list)
                        iterable = file_list if show_progress and TQDM_AVAILABLE else None
                        if iterable:
                            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Unpacking archive", leave=False, ascii=use_ascii) as pbar:
                                for file in iterable:
                                    pbar.set_description(f"Unpacking {Path(file.filename).name}")
                                    zipf.extract(member=file, path=extract_dir)
                                    pbar.update(file.file_size)
                        else:
                            zipf.extractall(path=extract_dir)
                    if show_progress: print("\n✅ Unpacking complete.")
                    return extract_dir / decrypted_path.stem
                except Exception as e:
                    if show_progress: print(f"❌ Failed to unpack archive: {e}")
                finally:
                    if decrypted_path.exists(): decrypted_path.unlink()
            else:
                if show_progress: print(f"✅ Decrypted successfully: {decrypted_path.name}")
                return decrypted_path
    return None

def batch_process_files(files_to_process: List[Path], password: str, action: str, config: Dict) -> None:
    start_time = time.time()
    use_multiprocessing = config.get('enable_multiprocessing', 'no').lower() == 'yes'
    use_ascii = config.get('progress_bar_style', 'unicode').lower() == 'ascii'
    results: List[Dict] = []
    
    if use_multiprocessing and TQDM_AVAILABLE:
        total_cores = os.cpu_count() or 1
        worker_count_config = int(config.get('worker_processes', 0))
        workers = total_cores if worker_count_config == 0 else min(worker_count_config, total_cores)
        if config.get('debug_mode', 'no').lower() == 'yes' and PSUTIL_AVAILABLE:
             print(f"DEBUG INFO: Multiprocessing enabled. System has {total_cores} cores. Configured to use {workers}.")
        tasks = [(str(f), password, action, config, False) for f in files_to_process]
        try:
            with multiprocessing.Pool(processes=workers) as pool, tqdm(total=len(tasks), desc=f"{action.capitalize()}ing batch", ascii=use_ascii) as pbar:
                for result in pool.imap_unordered(worker_process_single_file, tasks):
                    results.append(result)
                    pbar.set_description(f"Finished: {Path(result['original']).name}")
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

    if use_multiprocessing:
        print("\n--- Batch Summary ---")
        success_count = 0
        sorted_results = sorted(results, key=lambda x: x['original'])
        for res in sorted_results:
            if res['status'] == 'success':
                success_count += 1
                if 'checksum' in res and res['checksum']:
                    print(f"✅ {action.capitalize()}ed: {Path(res['result']).name} | SHA256: {res['checksum'][:12]}...")
                else:
                    print(f"✅ {action.capitalize()}ed: {Path(res['result']).name}")
            else:
                print(f"❌ FAILED: {Path(res['original']).name} | Reason: {res.get('message', 'Unknown')}")
        print(f"---------------------\n{success_count}/{len(results)} files processed successfully.")

    duration = time.time() - start_time
    print(f"\n✅ Batch operation finished in {utils.format_duration(duration)}.")

def process_folder_in_place(path: Path, password: str, action: str, config: Dict) -> None:
    print("-" * 30); print(f"{action.capitalize()}ing all files in folder '{path}'...")
    extension = config['encrypted_file_extension']
    files_to_process = [item for item in path.rglob('*') if item.is_file() and ((action == 'encrypt' and item.suffix != extension) or (action == 'decrypt' and item.suffix == extension))]
    if not files_to_process:
        print("No files to process."); return
    batch_process_files(files_to_process, password, action, config)

def create_and_encrypt_archive(path_str: str, password: str, config: Dict) -> None:
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
    double_encrypt = config.get('double_encryption_on_archive', 'no').lower() == 'yes'
    temp_dir, source_to_archive = None, clean_path
    try:
        if double_encrypt:
            # ... double encryption logic ...
            pass
        
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
        if utils.confirm_deletion(clean_path, config):
            remove_directory_robustly(clean_path)
        else: print("ℹ️ Original folder was kept.")
    finally:
        if temp_dir and temp_dir.exists(): shutil.rmtree(temp_dir); print("Temporary directory cleaned up.")
    duration = time.time() - start_time
    print(f"\n✅ Archive creation and encryption finished in {utils.format_duration(duration)}.")

def encrypt_text(text: str, password: str, config: Dict) -> str:
    encrypted_bytes = crypto.encrypt_text_data(text.encode('utf-8'), password, config)
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
def decrypt_text(encrypted_text: str, password: str, config: Dict) -> str:
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
        decrypted_data = crypto.decrypt_text_data(encrypted_bytes, password, config)
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
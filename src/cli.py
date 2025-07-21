# src/cli.py
import glob
import os
import sys
import time
from pathlib import Path
from typing import Dict

from . import core
from . import utils

def handle_file_menu(config: Dict) -> None:
    title_suffix = utils.get_title_suffix(config)
    while True:
        os.system('cls' if os.name == 'nt' else 'clear'); print(f"--- Category: Files ---{title_suffix}")
        print("  [1] Encrypt single file\n  [2] Decrypt single file\n  [3] Encrypt files by pattern\n  [9] Back to main menu")
        choice = input("> ")
        if choice == '1':
            path = Path(input("Path to file: "))
            if path.is_file():
                if pwd := utils.get_password(config):
                    start_time = time.time()
                    core.process_single_file_main_thread(path, pwd, 'encrypt', config)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {utils.format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '2':
            path = Path(input("Path to encrypted file: "))
            if path.is_file():
                if pwd := utils.get_password(config, confirm=False):
                    start_time = time.time()
                    core.process_single_file_main_thread(path, pwd, 'decrypt', config)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {utils.format_duration(duration)}.")
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
                        if pwd := utils.get_password(config):
                            core.batch_process_files(files_to_process, pwd, 'encrypt', config)
                    else: print("Operation cancelled.")
            except Exception as e: print(f"❌ An error occurred: {e}")
        elif choice == '9': break
        input("\nPress Enter to continue...")

def handle_folder_menu(config: Dict) -> None:
    title_suffix = utils.get_title_suffix(config)
    while True:
        os.system('cls'if os.name == 'nt' else 'clear');print(f"--- Category: Folders ---{title_suffix}")
        print("  [1] Encrypt folder (in-place)\n  [2] Decrypt folder (in-place)\n  [3] Encrypt folder as archive\n  [4] Decrypt and unpack standard archive\n  [5] Decrypt and unpack DOUBLE-ENCRYPTED(config) archive\n  [9] Back to main menu")
        choice = input("> ")
        if choice in ['1', '2']:
            action='encrypt'if choice == '1' else'decrypt'
            path = Path(input("Path to folder: "))
            if path.is_dir():
                if pwd := utils.get_password(config, confirm=(action=='encrypt')): core.process_folder_in_place(path, pwd, action, config)
            else: print("❌ Invalid folder path.")
        elif choice == '3':
            path_str = input("Path to folder (e.g., 'docs' or 'docs/*'): ")
            if pwd := utils.get_password(config): core.create_and_encrypt_archive(path_str, pwd, config)
        elif choice == '4':
            path = Path(input("Path to encrypted archive: "))
            if path.is_file():
                if pwd := utils.get_password(config, confirm=False):
                    start_time = time.time()
                    core.process_single_file_main_thread(path, pwd, 'decrypt', config, unpack=True)
                    duration = time.time() - start_time
                    print(f"\n✅ Operation finished in {utils.format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '5':
            path = Path(input("Path to double-encrypted archive: "))
            if path.is_file():
                start_time = time.time()
                print("\n--- Step 1: Decrypting the outer archive ---")
                outer_pwd = utils.get_password(config, confirm=False, prompt_message="Enter password for the ARCHIVE file: ")
                if outer_pwd:
                    unpacked_folder_path = core.process_single_file_main_thread(path, outer_pwd, 'decrypt', config, unpack=True)
                    if unpacked_folder_path and unpacked_folder_path.is_dir():
                        print("\n--- Step 2: Decrypting inner files ---")
                        inner_pwd = utils.get_password(config, confirm=False, prompt_message=f"Enter password for files INSIDE '{unpacked_folder_path.name}': ")
                        if inner_pwd:
                            core.process_folder_in_place(unpacked_folder_path, inner_pwd, 'decrypt', config)
                        else: print("Operation aborted. Folder is unpacked but its content remains encrypted.")
                duration = time.time() - start_time
                print(f"\n✅ Operation finished in {utils.format_duration(duration)}.")
            else: print("❌ Invalid file path.")
        elif choice == '9': break
        else: print("Invalid selection.")
        input("\nPress Enter to continue...")

def handle_text_menu(config: Dict) -> None:
    title_suffix = utils.get_title_suffix(config)
    while True:
        os.system('cls'if os.name == 'nt' else 'clear'); print(f"--- Category: Text Messages ---{title_suffix}")
        print("  [1] Encrypt text message\n  [2] Decrypt text message\n  [9] Back to main menu")
        choice = input("> ")
        if choice == '1':
            text = input("Enter the text:\n> ")
            if pwd := utils.get_password(config):
                print(f"\nYOUR ENCRYPTED MESSAGE:\n{core.encrypt_text(text, pwd, config)}")
        elif choice == '2':
            text = input("Paste the encrypted message:\n> ")
            if pwd := utils.get_password(config, confirm=False):
                print(f"\nYOUR DECRYPTED MESSAGE:\n{core.decrypt_text(text, pwd, config)}")
        elif choice == '9': break
        input("\nPress Enter to continue...")

def handle_config_menu(config: Dict) -> None:
    title_suffix = utils.get_title_suffix(config)
    os.system('cls'if os.name == 'nt' else 'clear');print(f"--- Current Configuration (config.ini) ---{title_suffix}")
    config_path = Path('config.ini')
    try:
        print(config_path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        print("❌ 'config.ini' not found.");input("\nPress Enter...");return
    print("-" * 45)
    if input("Press 'e' to edit, or any other key to return: ").lower() == 'e':
        utils.open_file_in_editor(config_path)
        input("\nPress Enter to continue...")

def handle_debug_menu(config: Dict) -> None:
    title_suffix = utils.get_title_suffix(config)
    is_debug = config.get('debug_mode', 'no').lower() == 'yes'
    while True:
        os.system('cls'if os.name == 'nt' else 'clear');
        print(f"--- Category: Debug/Analysis Tools ---{title_suffix}")
        print("  [1] Read metadata from encrypted file")
        print("  [2] Verify file checksum (SHA256/512)")
        if is_debug:
            print("  [3] Run Automated Test Suite")
        print("  [9] Back to main menu")
        choice = input("> ")

        if choice == '1':
            path = Path(input("Path to encrypted file: "))
            core.read_file_metadata(path)
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
                    if calculated_hash := utils.calculate_hash(path, config, algorithm):
                        print(f"  > Calculated: {calculated_hash}\n  > Expected:   {expected_hash}")
                        if calculated_hash == expected_hash: print("\n✅ Match! The file is not corrupted.")
                        else: print("\n❌ MISMATCH! The file may be corrupted or has been altered.")
        elif choice == '3' and is_debug:
            core.run_test_suite(config)
        elif choice == '9': break
        else: print("Invalid selection.")
        input("\nPress Enter to continue...")
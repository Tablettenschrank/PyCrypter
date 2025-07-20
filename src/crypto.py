import base64
import os
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Import optional dependencies, with fallbacks defined in main.py
try:
    from tqdm import tqdm
    import psutil
    TQDM_AVAILABLE = True
    PSUTIL_AVAILABLE = True
except ImportError:
    # This is just to satisfy static analysis; main.py handles the real import and fallback
    pass

# --- Constants ---
CHUNK_SIZE_KB_DEFAULT = 4096

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
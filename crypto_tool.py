import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Ein fester "Salt" wird hier zur Vereinfachung verwendet.
SALT = b'dein_super_geheimer_salt'

def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """Leitet aus einem Passwort einen kryptographischen Schlüssel ab."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# --- Algorithmus 1: Fernet ---

def encrypt_data(data: bytes, key: bytes, algorithm: str) -> bytes:
    """Universelle Verschlüsselungsfunktion für Bytes."""
    if algorithm == 'aes-gcm':
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        # Nonce und verschlüsselte Daten für die Speicherung kombinieren
        return nonce + encrypted_data
    else: # Fallback auf Fernet
        f_key = base64.urlsafe_b64encode(key)
        fernet = Fernet(f_key)
        return fernet.encrypt(data)

def decrypt_data(encrypted_data: bytes, key: bytes, algorithm: str) -> bytes:
    """Universelle Entschlüsselungsfunktion für Bytes."""
    try:
        if algorithm == 'aes-gcm':
            aesgcm = AESGCM(key)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            return aesgcm.decrypt(nonce, ciphertext, None)
        else: # Fallback auf Fernet
            f_key = base64.urlsafe_b64encode(key)
            fernet = Fernet(f_key)
            return fernet.decrypt(encrypted_data)
    except (InvalidToken, TypeError, IndexError):
        # Fängt Fehler ab, die auf ein falsches Passwort, einen falschen Algorithmus oder eine beschädigte Datei hindeuten.
        raise ValueError("Entschlüsselung fehlgeschlagen. Passwort/Algorithmus falsch oder Daten korrupt.")


# --- Handler für Dateien und Ordner ---

def process_single_file(file_path: str, password: str, action: str, config: dict):
    """Ver- oder entschlüsselt eine einzelne Datei."""
    algorithm = config.get('default_algorithm', 'fernet').lower()
    extension = config['encrypted_file_extension']
    key = derive_key(password, SALT)
    
    print("-" * 30)
    print(f"Aktion: {action.capitalize()} | Algorithmus: {algorithm.upper()} | Datei: {os.path.basename(file_path)}")
    print("-" * 30)
    
    try:
        if action == 'encrypt':
            if file_path.endswith(extension):
                print(f"⚠️ Datei '{os.path.basename(file_path)}' scheint bereits verschlüsselt zu sein.")
                return
            with open(file_path, 'rb') as f:
                original_data = f.read()
            encrypted_content = encrypt_data(original_data, key, algorithm)
            encrypted_file_path = file_path + extension
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_content)
            os.remove(file_path)
            print(f"✅ Erfolgreich verschlüsselt: {os.path.basename(encrypted_file_path)}")

        elif action == 'decrypt':
            if not file_path.endswith(extension):
                print(f"⚠️ Datei '{os.path.basename(file_path)}' hat nicht die korrekte Endung ('{extension}').")
                return
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
            decrypted_content = decrypt_data(encrypted_content, key, algorithm)
            original_file_path = file_path[:-len(extension)]
            with open(original_file_path, 'wb') as f:
                f.write(decrypted_content)
            os.remove(file_path)
            print(f"✅ Erfolgreich entschlüsselt: {os.path.basename(original_file_path)}")
            
    except ValueError as e:
        print(f"❌ {e}")
    except Exception as e:
        print(f"❌ Ein unerwarteter Fehler ist aufgetreten: {e}")


def process_directory(directory_path: str, password: str, action: str, config: dict):
    """Durchläuft ein Verzeichnis und wendet die Aktion an."""
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            # Hier rufen wir jetzt die Logik für einzelne Dateien auf
            process_single_file(file_path, password, action, config)


# --- Handler für Textnachrichten ---

def encrypt_text(text: str, password: str, config: dict) -> str:
    """Verschlüsselt einen Text-String und gibt ihn als base64-String zurück."""
    algorithm = config.get('default_algorithm', 'fernet').lower()
    key = derive_key(password, SALT)
    
    encrypted_bytes = encrypt_data(text.encode('utf-8'), key, algorithm)
    # Rückgabe als Base64-String, damit er leicht kopiert werden kann.
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

def decrypt_text(encrypted_text: str, password: str, config: dict) -> str:
    """Entschlüsselt einen Base64-String und gibt den Originaltext zurück."""
    algorithm = config.get('default_algorithm', 'fernet').lower()
    key = derive_key(password, SALT)
    
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
        decrypted_bytes = decrypt_data(encrypted_bytes, key, algorithm)
        return decrypted_bytes.decode('utf-8')
    except ValueError as e:
        return f"❌ {e}"
    except Exception:
        return "❌ Fehler: Die Eingabe ist kein gültiger Base64-String oder ist beschädigt."
import os
import configparser
import getpass
from crypto_tool import process_directory, process_single_file, encrypt_text, decrypt_text

def load_config():
    """Lädt die Einstellungen aus der config.ini Datei."""
    config = configparser.ConfigParser()
    config.read('config.ini')
    if 'Settings' not in config:
        raise KeyError("Sektion [Settings] in config.ini nicht gefunden.")
    return config['Settings']

def show_menu(config):
    """Zeigt das Hauptmenü für den Benutzer an."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(" Python Encryption-Tool ")
    print("=" * 45)
    print(f"Aktiver Algorithmus (aus config.ini): {config.get('default_algorithm', 'N/A').upper()}")
    print("-" * 45)
    print("\n--- Ordner ---")
    print("  [1] Ordner verschlüsseln")
    print("  [2] Ordner entschlüsseln")
    print("\n--- Dateien ---")
    print("  [3] Einzelne Datei verschlüsseln")
    print("  [4] Einzelne Datei entschlüsseln")
    print("\n--- Textnachrichten ---")
    print("  [5] Textnachricht verschlüsseln")
    print("  [6] Textnachricht entschlüsseln")
    print("\n" + "-" * 45)
    print("  [9] Programm beenden")
    print("-" * 45)

def get_password():
    """Fragt sicher nach einem Passwort und dessen Bestätigung."""
    password = getpass.getpass("Bitte gib dein Passwort ein: ")
    if not password:
        print("\n Ein leeres Passwort ist nicht zulässig.")
        return None, None
    
    password_confirm = getpass.getpass("Bestätige dein Passwort: ")
    if password != password_confirm:
        print("\n  Die Passwörter stimmen nicht überein.")
        return None, None
    return password

def main():
    """Die Hauptfunktion, die das Programm steuert."""
    try:
        config = load_config()
    except Exception as e:
        print(f"Fehler beim Laden der Konfiguration: {e}")
        return

    while True:
        show_menu(config)
        choice = input("Wähle eine Option [1-6,9]: ")

        # --- Ordner- und Dateiverarbeitung ---
        if choice in ['1', '2']:
            action = 'encrypt' if choice == '1' else 'decrypt'
            path = input(f"Gib den Pfad zum Ordner ein: ")
            if os.path.isdir(path):
                password = getpass.getpass("Passwort für den Ordner: ")
                if password:
                    process_directory(path, password, action, config)
                else:
                    print("\n  Ein leeres Passwort ist nicht zulässig.")
            else:
                print("\n  Dies ist kein gültiger Ordnerpfad.")
        
        elif choice in ['3', '4']:
            action = 'encrypt' if choice == '3' else 'decrypt'
            path = input("Gib den Pfad zur Datei ein: ")
            if os.path.isfile(path):
                password = getpass.getpass(f"Passwort für die Datei '{os.path.basename(path)}': ")
                if password:
                    process_single_file(path, password, action, config)
                else:
                    print("\n  Ein leeres Passwort ist nicht zulässig.")
            else:
                print("\n  Dies ist kein gültiger Dateipfad.")

        # --- Textverarbeitung ---
        elif choice == '5':
            text_to_encrypt = input("Gib den Text ein, der verschlüsselt werden soll:\n> ")
            password = get_password()
            if password:
                encrypted_message = encrypt_text(text_to_encrypt, password, config)
                print("\n--- DEINE VERSCHLÜSSELTE NACHRICHT --- (zum Kopieren)")
                print(encrypted_message)
                print("-" * 40)
        
        elif choice == '6':
            encrypted_message = input("Füge die verschlüsselte Nachricht ein:\n> ")
            password = getpass.getpass("Passwort zur Entschlüsselung: ")
            if password and encrypted_message:
                decrypted_message = decrypt_text(encrypted_message, password, config)
                print("\n--- DEINE ENTSCHLÜSSELTE NACHRICHT ---")
                print(decrypted_message)
                print("-" * 40)

        # --- Programm beenden ---
        elif choice == '9':
            print("Programm wird beendet. Bye ")
            break
        
        else:
            print("\nUngültige Eingabe.")

        # Warte auf den Benutzer, bevor das Menü neu gezeichnet wird
        if choice in ['1', '2', '3', '4', '5', '6']:
            input("\nDrücke Enter, um zum Menü zurückzukehren.")

if __name__ == "__main__":
    main()
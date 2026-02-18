#!/usr/bin/env python3
"""
ALKANE - CRYPTOKANE
Secure CLI Tool
"""

import secrets
import string
import os
import sys
import getpass
import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import bcrypt
import argon2

try:
    import readline

    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind(r'"\C-h": backward-delete-char')
    readline.parse_and_bind(r'"\e[3~": delete-char')
except ImportError:
    pass


class Colors:
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    END = "\033[0m"


def print_banner():
    banner = f"""
▄█▀ ▄▄▄▄▄▄▄ ▀█▄
▀█████████████▀
    █▄███▄█
     █████
     █▀█▀█
┏┓┳┓┓┏┏┓┏┳┓┏┓┓┏┓┏┓┳┓┏┓
┃ ┣┫┗┫┃┃ ┃ ┃┃┃┫ ┣┫┃┃┣
┗┛┛┗┗┛┣┛ ┻ ┗┛┛┗┛┛┗┛┗┗┛
    {Colors.BOLD}╔══════════════════════════════════════════════════════════╗{Colors.END}{Colors.RED}
    ║ {Colors.BOLD}{Colors.WHITE}ALKANE - CRYPTOKANE{Colors.END}{Colors.RED}                                      ║
    ║ {Colors.YELLOW}Secure encryption for your data{Colors.RED}                          ║
    ║ {Colors.CYAN}We will die seeking justice, not revenge.{Colors.RED}                ║
    {Colors.BOLD}╚══════════════════════════════════════════════════════════╝{Colors.END}{Colors.RED}


    {Colors.BOLD}HOW TO USE:{Colors.END}
    1. python3 secure_cli.py   or   ./secure_cli.py
    2. Choose 1-9
    3. Passwords hidden (getpass)
    4. Keys → never share
    5. Encrypted files: .alk
    6. Ctrl+C to exit or Press 9

    {Colors.RED}Stay secure.{Colors.END}
    """
    print(banner)
    sys.stdout.flush()


def log_key(key_str, description):
    log_file = "alkane_keys.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {description} | Key: {key_str}\n"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"{Colors.YELLOW}Key logged to: {os.path.abspath(log_file)}{Colors.END}")


def show_progress(current, total, action="Processing"):
    if total == 0:
        return
    percent = int((current / total) * 100)
    spinner = ["/", "-", "\\", "|"][int(current / 1024) % 4]
    sys.stdout.write(f"\r{action}: {percent}% {spinner}")
    sys.stdout.flush()


def color_strength(result):
    if "Strong" in result:
        return f"{Colors.GREEN}{result}{Colors.END}"
    elif "Weak" in result:
        return f"{Colors.RED}{result}{Colors.END}"
    return f"{Colors.YELLOW}{result}{Colors.END}"


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def check_password_strength(password):
    if len(password) < 12:
        return "Weak: At least 12 chars"
    if not any(c.islower() for c in password):
        return "Weak: Needs lowercase"
    if not any(c.isupper() for c in password):
        return "Weak: Needs uppercase"
    if not any(c.isdigit() for c in password):
        return "Weak: Needs digit"
    if not any(c in string.punctuation for c in password):
        return "Weak: Needs special char"
    return "Strong: Good password"


def hash_password(password, algorithm="bcrypt"):
    if algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return "bcrypt:" + hashed.decode()
    elif algorithm == "argon2":
        hasher = argon2.PasswordHasher()
        return "argon2:" + hasher.hash(password)
    raise ValueError("Invalid algorithm")


def verify_hashed_password(password, hashed):
    if hashed.startswith("bcrypt:"):
        return bcrypt.checkpw(password.encode(), hashed[7:].encode())
    elif hashed.startswith("argon2:"):
        hasher = argon2.PasswordHasher()
        try:
            hasher.verify(hashed[7:], password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    raise ValueError("Invalid hash format")


def derive_aes_key(key_bytes: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(key_bytes)


def generate_key():

    return secrets.token_bytes(32)


def encrypt_file(file_path: str, key_bytes: bytes) -> str:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    out_path = file_path + ".alk"
    chunk_size = 1024 * 1024  # 1 MiB

    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key = derive_aes_key(key_bytes, salt)
    aesgcm = AESGCM(aes_key)

    file_size = os.path.getsize(file_path)
    processed = 0

    with open(file_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(salt + nonce)

        while chunk := fin.read(chunk_size):
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
            fout.write(encrypted_chunk)
            processed += len(chunk)
            show_progress(processed, file_size, "Encrypting")

    print("\nEncryption complete.")
    log_key(key_bytes.hex(), f"Encrypted file: {file_path} → {out_path}")
    return os.path.abspath(out_path)


def decrypt_file(enc_path: str, key_bytes: bytes) -> str | None:
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"File not found: {enc_path}")

    chunk_size = 1024 * 1024
    file_size = os.path.getsize(enc_path)
    processed = 0

    with open(enc_path, "rb") as fin:
        salt = fin.read(16)
        nonce = fin.read(12)
        if len(salt) != 16 or len(nonce) != 12:
            print(f"{Colors.RED}Invalid file format{Colors.END}")
            return None

        aes_key = derive_aes_key(key_bytes, salt)
        aesgcm = AESGCM(aes_key)

        out_path = enc_path.replace(".alk", "_decrypted")

        with open(out_path, "wb") as fout:
            while chunk := fin.read(chunk_size + 16):
                try:
                    decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                    fout.write(decrypted_chunk)
                except InvalidTag:
                    print(f"\n{Colors.RED}Wrong key or corrupted file!{Colors.END}")
                    try:
                        os.remove(out_path)
                    except:
                        pass
                    return None
                processed += len(chunk) - 16
                show_progress(processed, file_size - 28, "Decrypting")

    print("\nDecryption complete.")
    return os.path.abspath(out_path)


def encrypt_data(data: str, key_bytes: bytes) -> str:
    fernet_key = Fernet(key_bytes[:32])
    enc = fernet_key.encrypt(data.encode()).decode()
    log_key(key_bytes.hex(), "Encrypted text data")
    return enc


def decrypt_data(enc_data: str, key_bytes: bytes) -> str | None:
    fernet_key = Fernet(key_bytes[:32])
    try:
        return fernet_key.decrypt(enc_data.encode()).decode()
    except InvalidToken:
        return None


def main_menu():
    print_banner()
    while True:
        print("\n=== CRYPTOKANE ===")
        print("1. Generate password")
        print("2. Check strength + hash")
        print("3. Encrypt file (.alk)")
        print("4. Decrypt file")
        print("5. Encrypt text")
        print("6. Decrypt text")
        print("7. Hash password")
        print("8. Verify hash")
        print("9. Exit")
        sys.stdout.flush()

        try:
            ch = input("→ ").strip()
            if ch == "1":
                l = int(input("Length [16]: ") or 16)
                print("Password:", generate_strong_password(l))
            elif ch == "2":
                pw = getpass.getpass("Password: ")
                strength = check_password_strength(pw)
                print("Strength:", color_strength(strength))
                if "Strong" in strength:
                    if input("Hash? y/n: ").lower().startswith("y"):
                        algo = (
                            input("bcrypt/argon2 [bcrypt]: ").strip().lower()
                            or "bcrypt"
                        )
                        hashed = hash_password(pw, algo)
                        print(f"Hashed ({algo}): {hashed}")
                        if input("Save? y/n: ").lower().startswith("y"):
                            fp = input("File path: ").strip()
                            nk = input("New key? y/n [n]: ").strip().lower() or "n"
                            save_hash_to_file(hashed, fp, nk)
            elif ch == "3":
                fp = input("File path: ").strip()
                k = generate_key()
                print(
                    f"{Colors.RED}{Colors.BOLD}⚠️ KEY (SAVE SAFELY): {k.hex()}{Colors.END}"
                )
                print("Encrypted file:", encrypt_file(fp, k))
            elif ch == "4":
                fp = input("Encrypted file (.alk): ").strip()
                k_str = getpass.getpass("Key (hex): ")
                try:
                    k_bytes = bytes.fromhex(k_str)
                except ValueError:
                    print(f"{Colors.RED}Invalid hex key!{Colors.END}")
                    continue
                res = decrypt_file(fp, k_bytes)
                print(
                    "Decrypted:",
                    res if res else f"{Colors.RED}Failed (key?){Colors.END}",
                )
            elif ch == "5":
                t = input("Text: ").strip()
                k = generate_key()
                print(
                    f"{Colors.RED}{Colors.BOLD}⚠️ KEY (SAVE SAFELY): {k.hex()}{Colors.END}"
                )
                print("Encrypted:", encrypt_data(t, k))
            elif ch == "6":
                t = input("Encrypted text: ").strip()
                k_str = getpass.getpass("Key (hex): ")
                try:
                    k_bytes = bytes.fromhex(k_str)
                except ValueError:
                    print(f"{Colors.RED}Invalid hex key!{Colors.END}")
                    continue
                res = decrypt_data(t, k_bytes)
                if res:
                    print(f"Decrypted: {Colors.GREEN}{res}{Colors.END}")
                else:
                    print(f"{Colors.RED}Wrong key or invalid data!{Colors.END}")
            elif ch == "7":
                pw = getpass.getpass("Password: ")
                algo = input("bcrypt/argon2 [bcrypt]: ").strip().lower() or "bcrypt"
                hashed = hash_password(pw, algo)
                print(f"Hashed ({algo}): {hashed}")
                if input("Save? y/n: ").lower().startswith("y"):
                    fp = input("File: ").strip()
                    nk = input("New key? y/n [n]: ").strip().lower() or "n"
                    save_hash_to_file(hashed, fp, nk)
            elif ch == "8":
                pw = getpass.getpass("Password: ")
                if input("From file? y/n: ").lower().startswith("y"):
                    fp = input("File: ").strip()
                    k_str = getpass.getpass("Key (hex): ")
                    try:
                        k_bytes = bytes.fromhex(k_str)
                    except ValueError:
                        print(f"{Colors.RED}Invalid hex key!{Colors.END}")
                        continue
                    h = load_hash_from_file(fp, k_bytes)
                    if h is None:
                        print(f"{Colors.RED}Failed to load{Colors.END}")
                        continue
                else:
                    h = input("Hash: ").strip()
                if verify_hashed_password(pw, h):
                    print(f"{Colors.GREEN}Correct!{Colors.END}")
                else:
                    print(f"{Colors.RED}Wrong!{Colors.END}")
            elif ch == "9":
                print("See you soon")
                break
            else:
                print("Invalid.")
        except KeyboardInterrupt:
            print("\nSee you soon")
            break
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")


if __name__ == "__main__":
    main_menu()


# your friend alkane

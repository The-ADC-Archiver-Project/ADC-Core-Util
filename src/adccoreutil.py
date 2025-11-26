#!/usr/bin/env python3
import os
import sys
import base64
import zlib
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def parma_decompress(data):
    try:
        return zlib.decompress(data)
    except zlib.error as e:
        print(f"Decompress error: {e}")
        return None


def extract_adc(archive_path):
    out_dir = os.path.dirname(os.path.abspath(archive_path))
    with open(archive_path, "rb") as f:
        header = f.read(8)
        if header == b"ADCARCH\x00":
            salt = f.read(16)
            pwd = getpass.getpass("Enter password for archive: ")
            key = derive_key_from_password(pwd, salt)
            fernet = Fernet(key)
            encrypted = True
        else:
            f.seek(0)
            encrypted = False

        files_to_extract = []

        while True:
            ln_bytes = f.read(2)
            if not ln_bytes:
                break
            name_len = int.from_bytes(ln_bytes, "big")
            name = f.read(name_len).decode("utf-8", errors="ignore")
            data_len = int.from_bytes(f.read(8), "big")
            data = f.read(data_len)
            if encrypted:
                try:
                    data = fernet.decrypt(data)
                except Exception as e:
                    print(f"Failed to decrypt {name}: {e}")
                    continue
            files_to_extract.append((name, data))

        for name, comp in files_to_extract:
            dec = parma_decompress(comp)
            if dec is None:
                print(f"Failed to decompress {name}")
                continue
            out_path = os.path.join(out_dir, name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as w:
                w.write(dec)
            print(f"Extracted: {out_path}")

    print(f"Extraction complete to {out_dir}")


def main():
    if len(sys.argv) < 2:
        print("Usage: adccoreutil <archive.adc>")
        return
    archive_file = sys.argv[1]
    if not os.path.isfile(archive_file):
        print(f"File not found: {archive_file}")
        return
    extract_adc(archive_file)


if __name__ == "__main__":
    main()

import os
import argparse
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def generate_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(key, in_filename, out_filename):
    chunksize = 64 * 1024
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = Padding.pad(chunk, 16)
                outfile.write(cipher.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename):
    chunksize = 64 * 1024
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                try:
                    outfile.write(Padding.unpad(decrypted_chunk, 16))
                except Exception as e:
                    print(
                        f"Password or salt incorrect. Unable to decrypt, raise exception :{e}")
                    return


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a file using AES.")
    parser.add_argument("-a", "--action", choices=[
                        "encrypt", "decrypt"], help="Whether to encrypt or decrypt the file.")
    args = parser.parse_args()

    # Create a directory to store the salt and encrypted files
    encrypted_dir = "encrypted_files"
    os.makedirs(encrypted_dir, exist_ok=True)

    # Prompt the user for a password
    password = getpass("Enter a password: ")

    # Encrypt or decrypt the file based on the user's choice
    if args.action == "encrypt":
        # Generate a random salt and store it in the directory
        salt = os.urandom(16)
        with open(os.path.join(encrypted_dir, "salt"), "wb") as salt_file:
            salt_file.write(salt)

        # Generate a key from the password and salt
        with open(os.path.join(encrypted_dir, "salt"), "rb") as salt_file:
            salt = salt_file.read()
        key = generate_key(password.encode("utf-8"), salt)
        in_filename = "input_file.txt"
        out_filename = os.path.join(encrypted_dir, "encrypted_file.bin")
        encrypt_file(key, in_filename, out_filename)
    else:
        # If decrypting, read the salt from the directory
        with open(os.path.join(encrypted_dir, "salt"), "rb") as salt_file:
            salt = salt_file.read()
        # Generate the key from the password and salt
        key = generate_key(password.encode("utf-8"), salt)

        # Decrypt the file using the generated key
        in_filename = os.path.join(encrypted_dir, "encrypted_file.bin")
        out_filename = "decrypted_file.txt"
        decrypt_file(key, in_filename, out_filename)


if __name__ == "__main__":
    main()

import os
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


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
                outfile.write(Padding.unpad(decrypted_chunk, 16))


# Create a directory to store the salt and encrypted files
encrypted_dir = "encrypted_files"
os.makedirs(encrypted_dir, exist_ok=True)

# # Prompt the user for a password
# password = getpass("Enter a password: ")

# salt = os.urandom(16)
# with open(os.path.join(encrypted_dir, "salt"), "wb") as salt_file:
#     salt_file.write(salt)

# # Generate a key from the password and salt
# with open(os.path.join(encrypted_dir, "salt"), "rb") as salt_file:
#     salt = salt_file.read()
# key = generate_key(password.encode("utf-8"), salt)

# # Encrypt a file using the generated key
# in_filename = "input_file.txt"
# out_filename = os.path.join(encrypted_dir, "encrypted_file.bin")
# encrypt_file(key, in_filename, out_filename)

# Later, when the user wants to decrypt the file...

# Prompt the user for the password again
password = getpass("Enter the password: ")

# Generate the key from the password and salt
with open(os.path.join(encrypted_dir, "salt"), "rb") as salt_file:
    salt = salt_file.read()
key = generate_key(password.encode("utf-8"), salt)

# Decrypt the file using the generated key
in_filename = os.path.join(encrypted_dir, "encrypted_file.bin")
out_filename = "decrypted_file.txt"
decrypt_file(key, in_filename, out_filename)

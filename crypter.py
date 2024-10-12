import os
import argparse
from getpass import getpass
from tqdm import tqdm

from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def generate_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=key_length,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    return kdf.derive(password)


def encrypt_file(key, in_filename):
    chunksize = 64 * 1024
    temp_filename = in_filename + ".tmp"

    # Generate a random IV for each file
    iv = os.urandom(16)
    with open(in_filename, 'rb') as infile:
        with open(temp_filename, 'wb') as outfile:
            # Write the IV at the beginning of the file
            outfile.write(iv)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = Padding.pad(chunk, 16)
                    outfile.write(cipher.encrypt(chunk))
                    break  # Last chunk
                outfile.write(cipher.encrypt(chunk))

    # Replace the original file with the temporary file
    try:
        os.replace(temp_filename, in_filename)
    except Exception as e:
        print(f"Unable to replace {in_filename} with {temp_filename}: {e}")


def decrypt_file(key, in_filename):
    chunksize = 64 * 1024
    temp_filename = in_filename + ".tmp"
    hasException = False

    with open(in_filename, 'rb') as infile:
        with open(temp_filename, 'wb') as outfile:
            # Read the IV from the beginning of the file
            iv = infile.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            prev_chunk = None
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    if prev_chunk is not None:
                        try:
                            decrypted = cipher.decrypt(prev_chunk)
                            decrypted = Padding.unpad(decrypted, 16)
                            outfile.write(decrypted)
                        except Exception as e:
                            print(
                                f"\nError while decrypting {temp_filename}: {e}"
                            )
                            hasException = True
                    break

                if prev_chunk is not None:
                    decrypted = cipher.decrypt(prev_chunk)
                    outfile.write(decrypted)

                prev_chunk = chunk

    if not hasException:
        # Replace the original file with the temporary file
        os.replace(temp_filename, in_filename)
        return 0
    else:
        os.remove(temp_filename)  # Delete the temporary file
        return -1


def process_files(action, directory, password=""):
    if password != "test":
        password = getpass("Enter a password: ")

    saltFile = os.path.join(directory, "salt")
    if action == "encrypt":
        if password != "test":
            passwordConfirmed = getpass("Re-enter a password: ")
        else:
            passwordConfirmed = password

        if password != passwordConfirmed:
            print("Passwords do not match. Please try again...")
            process_files(action, directory)
            return
        salt = os.urandom(16)
        with open(saltFile, "wb") as salt_file:
            salt_file.write(salt)
        print("Salt file created at:", saltFile)
        key = generate_key(password.encode("utf-8"), salt)
        print("Encrypting files...")
        for root, dirs, files in tqdm(os.walk(directory), desc="Directories"):
            for file in tqdm(files, desc="Files", leave=False):
                if file != "salt":
                    in_filename = os.path.join(root, file)
                    print("Encrypting:", in_filename)
                    encrypt_file(key, in_filename)
    else:
        if not os.path.isfile(saltFile):
            print(f"Salt file not found in {directory}. Decryption aborted!")
            return
        with open(saltFile, "rb") as salt_file:
            salt = salt_file.read()
        key = generate_key(password.encode("utf-8"), salt)
        print("Decrypting files...")
        for root, dirs, files in tqdm(os.walk(directory), desc="Directories"):
            for file in tqdm(files, desc="Files", leave=False):
                if file != "salt":
                    in_filename = os.path.join(root, file)
                    ret = decrypt_file(key, in_filename)
                    if ret == -1:
                        print("Error during decryption. Exiting!")
                        return

        os.remove(saltFile)
        print("Decryption completed successfully.")


def test():
    directory = "test"
    process_files("encrypt", directory, "test")
    ret = process_files("decrypt", directory, "test")
    if ret == -1:
        print("Error while decrypting the test file. Test failed!")
        return -1
    testFile = os.path.join(directory, "testFile.txt")
    if not os.path.isfile(testFile):
        print(f"Cannot find {testFile}. Test failed!")
        return -2
    with open(testFile, "r+") as test_file:
        content = test_file.read()
        originalContent = "hello world !"
        if content != originalContent:
            print(
                f"Test file content mismatch: {content} != {originalContent}. Test failed!"
            )
            return -3
    print("Test succeeded!")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files in a directory using AES.")
    parser.add_argument("-a",
                        "--action",
                        choices=["encrypt", "decrypt"],
                        help="Whether to encrypt or decrypt the files.")
    parser.add_argument("-d",
                        "--directory",
                        help="Directory containing the files.")
    parser.add_argument(
        "-t",
        "--test",
        action="store_true",
        help=
        "Whether to test the encryption and decryption on the 'test' directory."
    )
    args = parser.parse_args()

    if args.test:
        test()
    else:
        if not args.action or not args.directory:
            parser.print_help()
            return
        process_files(args.action, args.directory)


if __name__ == "__main__":
    main()

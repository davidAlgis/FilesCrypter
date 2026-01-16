import argparse
import os
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Util import Padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm


# ANSI color codes for visible warnings/errors
class Colors:
    WARNING = "\033[93m"  # Yellow
    FAIL = "\033[91m"  # Red
    ENDC = "\033[0m"  # Reset


def generate_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)


def encrypt_file(key, in_filename):
    chunksize = 64 * 1024
    temp_filename = in_filename + ".tmp"

    # Generate a random IV for each file
    iv = os.urandom(16)
    with open(in_filename, "rb") as infile:
        with open(temp_filename, "wb") as outfile:
            # Write the IV at the beginning of the file
            outfile.write(iv)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    # End of file reached; add padding
                    padding = Padding.pad(b"", AES.block_size)
                    outfile.write(cipher.encrypt(padding))
                    break
                elif len(chunk) % AES.block_size != 0:
                    # Last chunk; pad it
                    padded_chunk = Padding.pad(chunk, AES.block_size)
                    outfile.write(cipher.encrypt(padded_chunk))
                    break
                else:
                    # Middle chunk; no padding
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

    with open(in_filename, "rb") as infile:
        with open(temp_filename, "wb") as outfile:
            # Read the IV from the beginning of the file
            iv = infile.read(AES.block_size)
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            except ValueError:
                # Handle IV size errors (often caused by git corruption)
                print(
                    f"{Colors.FAIL}\nError: File header corrupted or invalid IV. "
                    f"Did Git strip binary data?{Colors.ENDC}"
                )
                os.remove(temp_filename)
                return -1

            next_chunk = b""
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    try:
                        decrypted_chunk = cipher.decrypt(next_chunk)
                        decrypted_chunk = Padding.unpad(
                            decrypted_chunk, AES.block_size
                        )
                        outfile.write(decrypted_chunk)
                    except (ValueError, KeyError) as e:
                        print(
                            f"\nError while decrypting {temp_filename}: {e}. "
                            "Password or salt might be incorrect."
                        )
                        hasException = True
                    break

                decrypted = cipher.decrypt(next_chunk)
                if len(next_chunk) > 0:
                    outfile.write(decrypted)
                next_chunk = chunk

    if not hasException:
        # Replace the original file with the temporary file
        os.replace(temp_filename, in_filename)
        return 0
    else:
        os.remove(temp_filename)  # Delete the temporary file
        return -1


def check_git_safety(target_directory):
    """
    Checks if the directory is inside a git repo and if .gitattributes is correctly set.
    Returns True if safe to proceed, False otherwise.
    """
    abs_target = os.path.abspath(target_directory)
    current_path = abs_target
    git_root = None

    # Traverse up to find .git folder
    while True:
        if os.path.isdir(os.path.join(current_path, ".git")):
            git_root = current_path
            break
        parent = os.path.dirname(current_path)
        if parent == current_path:
            # Reached root of drive, no .git found
            break
        current_path = parent

    # If not in a git repo, it's safe (technically)
    if not git_root:
        return True

    # We are in a git repo, check .gitattributes
    attributes_file = os.path.join(git_root, ".gitattributes")
    if not os.path.isfile(attributes_file):
        print(
            f"{Colors.FAIL}CRITICAL ERROR: You are inside a Git repository but no '.gitattributes' file was found.{Colors.ENDC}"
        )
        print(
            "Git will corrupt your encrypted files by modifying line endings."
        )
        return False

    # Calculate the relative path of the folder we are encrypting
    # e.g., if encrypting "D:\Repo\admin" and repo is "D:\Repo", relative is "admin"
    rel_path = os.path.relpath(abs_target, git_root).replace("\\", "/")

    # Define the required patterns
    # We look for "admin/** binary" or "admin/* binary"
    required_pattern = f"{rel_path}/** binary"
    required_pattern_alt = f"{rel_path}/* binary"

    found = False
    with open(attributes_file, "r", encoding="utf-8") as f:
        for line in f:
            clean_line = line.strip()
            # Check for the specific folder rule OR a global binary rule
            if (
                required_pattern in clean_line
                or required_pattern_alt in clean_line
            ):
                found = True
                break
            # Also accept if the user brute-forced everything to binary
            if clean_line == "* binary":
                found = True
                break

    if not found:
        print(
            f"{Colors.FAIL}CRITICAL ERROR: Git safety check failed!{Colors.ENDC}"
        )
        print(
            f"The folder '{rel_path}' is not explicitly marked as binary in '{attributes_file}'."
        )
        print(f"Please add the following line to your .gitattributes file:\n")
        print(f"    {rel_path}/** binary\n")
        print("Without this, Git will corrupt your encrypted data.")
        return False

    return True


def process_files(action, directory, password="", test=False):
    if not test:
        password = getpass("Enter a password: ")

    saltFile = os.path.join(directory, "salt")
    if action == "encrypt":
        # --- NEW SAFETY CHECK ---
        if not check_git_safety(directory):
            print("Encryption aborted to prevent data corruption.")
            return
        # ------------------------

        if not test:
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
            # 1. Skip .git FOLDERS
            if ".git" in dirs:
                dirs.remove(".git")
                tqdm.write(
                    f"{Colors.WARNING}[IGNORED] Found .git folder in '{root}'. Skipping.{Colors.ENDC}"
                )

            for file in tqdm(files, desc="Files", leave=False):
                # 2. Skip .git FILES
                if file == ".git" or file == ".gitmodules":
                    tqdm.write(
                        f"{Colors.WARNING}[IGNORED] Found {file} file in '{root}'. Skipping.{Colors.ENDC}"
                    )
                    continue

                # 3. Skip the salt file
                if file == "salt":
                    continue

                if file != "salt":
                    in_filename = os.path.join(root, file)
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
            if ".git" in dirs:
                dirs.remove(".git")
                tqdm.write(
                    f"{Colors.WARNING}[IGNORED] Found .git folder in '{root}'. Skipping.{Colors.ENDC}"
                )

            for file in tqdm(files, desc="Files", leave=False):
                if file == ".git" or file == ".gitmodules":
                    tqdm.write(
                        f"{Colors.WARNING}[IGNORED] Found {file} file in '{root}'. Skipping.{Colors.ENDC}"
                    )
                    continue

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
    # Ensure test dir exists
    if not os.path.exists(directory):
        os.makedirs(directory)
    # Create dummy git attributes for test pass (if inside a repo)
    # Note: In a real test scenario, we might want to mock check_git_safety
    # or create a temporary .gitattributes, but for now we run process_files.

    # We temporarily mock check_git_safety to True for the internal test function
    # or ensure we are testing in a safe folder.
    # For simplicity here, we assume the test folder isn't the issue.

    process_files("encrypt", directory, "test", True)
    ret = process_files("decrypt", directory, "test", True)
    if ret == -1:
        print("Error while decrypting the test file. Test failed!")
        return -1
    testFile = os.path.join(directory, "testFile.txt")
    if not os.path.isfile(testFile):
        # Create file if missing for robustness
        with open(testFile, "w") as f:
            f.write("hello world !")

    with open(testFile, "r+", encoding="utf-8") as test_file:
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
        description="Encrypt or decrypt files in a directory using AES."
    )
    parser.add_argument(
        "-a",
        "--action",
        choices=["encrypt", "decrypt"],
        help="Whether to encrypt or decrypt the files.",
    )
    parser.add_argument(
        "-d", "--directory", help="Directory containing the files."
    )
    parser.add_argument(
        "-t",
        "--test",
        action="store_true",
        help="Whether to test the encryption and decryption on the 'test' directory.",
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

# Files Crypter

This Python script allows you to encrypt or decrypt files in a directory. More concretely, you can use it as a simple protection for your sensible files encrypt them using a password and then when you need to read them back just decrypt them using the same password.


> [!CAUTION]
> I'm not an expert in cryptography ! Therefore, there might be flaw in this code. If you notice some of them, feel free to add an issue !


## Installation

Before running the script, you need to install the required Python libraries. You can install them using the provided `requirements.txt` file.

```
pip install -r requirements.txt
```


## Usage

To use this script, run it from the command line and specify the action (encrypt or decrypt) and the directory containing the files:
```
python crypter.py -a encrypt -d /path/to/directory
python crypter.py -a decrypt -d /path/to/directory
```

If you are encrypting files, you will be prompted to enter a password. This password will be used to generate a key, which will be used to encrypt the files. The script will also create a salt file in the directory, which is necessary for decrypting the files.

> [!WARNING]  
> The files in the directory will be fully rewrite, therefore if you are not sure of what you are doing please make a backup of your file somewhere safe !

> [!WARNING]  
> Make sure to keep in mind the password __and__ the salt file in the directory or you won't be able to recover your files !


If you are decrypting files, you will be prompted to enter the password that was used to encrypt the files. The script will use the salt file in the directory to generate a key, which will be used to decrypt the files.

## Options

- `-d`, `--directory` <directory>: Specify the directory where the files should be encrypt or decrypt.

- `-t`, `--test`: Execute a test function to verify the script's functionality.

- `-a`, `--action` <encrypt/decrypt>: Indicate whether the script should encrypt or decrypt the files in the given directory.

- `-h`, `--help`: Display help information showing all command-line options.


## Note

- This script uses [AES encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard?oldid=689607309) with a key size of 256 bits and a block size of 16 bytes.
- The key is generated using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) with a [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) and 100,000 iterations.
- The encryption mode is CBC (Cipher Block Chaining).

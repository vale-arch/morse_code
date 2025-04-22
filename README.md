# AES-128 CBC Encryption/Decryption Tool

This tool provides file encryption and decryption using AES-128 in CBC mode, implemented with OpenSSL 3.0 EVP APIs.

## Features

- File encryption/decryption using AES-128 CBC
- Base64 encoding/decoding of encrypted data using OpenSSL built-in functions
- Secure memory handling for sensitive data
- Comprehensive error checking
- OpenSSL 3.0 compliant implementation
- Key derivation from passphrase using PBKDF2
- Random IV generation for each encryption, stored with ciphertext

## Requirements

- OpenSSL 3.0 or later
- GCC or compatible C compiler
- Linux/Unix environment (tested on Ubuntu 22.04)

## Installation

1. Install OpenSSL development libraries:
```bash
sudo apt-get install libssl-dev
```

2. Compile the program:
```bash
gcc -o main main.c -lssl -lcrypto
```

## Usage

### Encrypt a file
```bash
./main encrypt input.txt
```
This will prompt for a passphrase, encrypt `input.txt` using a derived key and a random IV, and save the encrypted data (in Base64 format) back to the same file.

### Decrypt a file
```bash
./main decrypt input.txt
```
This will prompt for the passphrase used during encryption, decrypt `input.txt` (must be Base64 encoded encrypted data with prepended IV), and save the decrypted content back to the same file.

## Security Notes

1. **Key Security**: The implementation now derives the AES key from a user-provided passphrase using PBKDF2 with a salt, improving security over hardcoded keys.
2. **Initialization Vector**: A random IV is generated for each encryption and prepended to the ciphertext. This IV is used during decryption.
3. **Base64 Encoding**: Uses OpenSSL's built-in Base64 encoding and decoding functions for reliability and simplicity.
4. **Memory Security**: The implementation includes:
   - Secure zeroing of sensitive memory
   - Proper cleanup of OpenSSL contexts
   - Error checking for all cryptographic operations

## Implementation Details

- Uses OpenSSL 3.0 EVP API (not deprecated legacy APIs)
- Implements AES-128 in CBC mode with key derivation and random IV
- Uses OpenSSL built-in Base64 encoding/decoding
- Comprehensive error handling
- Proper resource cleanup

## Limitations

1. The tool overwrites input files - always keep backups
2. Not suitable for very large files (loads entire file into memory)
3. Passphrase must be remembered to decrypt data

## Future Improvements

- Add support for command-line key specification
- Add file integrity checks (HMAC)
- Support for larger files (streaming processing)
- Add progress indicators

## License

This code is provided as-is for educational purposes. Modify and use at your own risk.

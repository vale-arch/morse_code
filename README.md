# AES-128 CBC Encryption/Decryption Tool

This tool provides file encryption and decryption using AES-128 in CBC mode, implemented with OpenSSL 3.0 EVP APIs.

## Features

- File encryption/decryption using AES-128 CBC
- Base64 encoding/decoding of encrypted data
- Secure memory handling for sensitive data
- Comprehensive error checking
- OpenSSL 3.0 compliant implementation

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
This will encrypt `input.txt` and save the encrypted data (in Base64 format) back to the same file.

### Decrypt a file
```bash
./main decrypt input.txt
```
This will decrypt `input.txt` (must be Base64 encoded encrypted data) and save the decrypted content back to the same file.

## Security Notes

1. **Key Security**: The current implementation uses a hardcoded key for demonstration purposes. In production:
   - Use a proper key derivation function
   - Store keys securely (e.g., in a key management system)
   - Never hardcode keys in source files

2. **Initialization Vector**: The IV is currently set to all zeros. For better security:
   - Generate a random IV for each encryption
   - Store the IV with the encrypted data (typically prepended)

3. **Memory Security**: The implementation includes:
   - Secure zeroing of sensitive memory
   - Proper cleanup of OpenSSL contexts
   - Error checking for all cryptographic operations

## Implementation Details

- Uses OpenSSL 3.0 EVP API (not deprecated legacy APIs)
- Implements AES-128 in CBC mode
- Includes Base64 encoding/decoding
- Comprehensive error handling
- Proper resource cleanup

## Limitations

1. The tool overwrites input files - always keep backups
2. Not suitable for very large files (loads entire file into memory)
3. Lacks proper key management (for demonstration only)

## Future Improvements

- Add support for command-line key specification
- Implement random IV generation
- Add file integrity checks (HMAC)
- Support for larger files (streaming processing)
- Add progress indicators

## License

This code is provided as-is for educational purposes. Modify and use at your own risk.

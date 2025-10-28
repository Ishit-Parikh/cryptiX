# CryptiX
## A File Encryption & Decryption Tool

A command-line Java application for securely encrypting and decrypting files using AES-256 encryption with password-based key derivation.

## Features

- **Strong Encryption**: Uses AES-256 in CBC mode with PKCS5 padding
- **Password-Based**: Encrypts files using user-provided passwords
- **Secure Key Derivation**: Implements PBKDF2 with HMAC-SHA256 (65,536 iterations)
- **Memory Efficient**: Processes files in 4KB chunks, suitable for large files
- **Cross-Platform**: Works on any system with Java installed

## How It Works

### Encryption Process
1. Generates a random salt (16 bytes)
2. Derives a 256-bit encryption key from your password using PBKDF2
3. Generates a random Initialization Vector (IV) for CBC mode
4. Encrypts the file content in chunks
5. Stores salt and IV at the beginning of the encrypted file for decryption

### Decryption Process
1. Reads the salt and IV from the encrypted file
2. Derives the decryption key using the same password and salt
3. Decrypts the file content back to its original form

## Requirements

- Java Development Kit (JDK) 8 or higher
- No external dependencies required (uses built-in `javax.crypto` package)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Cryptography
```

2. Compile the Java files:
```bash
javac src/*.java
```

3. Run the application:
```bash
java -cp src Main
```

## Usage

### Running the Tool

When you run the program, you'll see an interactive menu:

```
=====================================
  File Encryption & Decryption Tool  
=====================================

What would you like to do?
1. Encrypt a file
2. Decrypt a file
Enter your choice (1 or 2):
```

### Encrypting a File

1. Select option `1`
2. Provide the path to the file you want to encrypt
3. Specify the output path for the encrypted file (e.g., `document.enc`)
4. Enter and confirm your password
5. The encrypted file will be created with the salt and IV embedded

**Example:**
```
Enter the path of the file to encrypt: document.txt
Enter the path for the encrypted file: document.enc
Enter encryption password: ********
Confirm password: ********
```

### Decrypting a File

1. Select option `2`
2. Provide the path to the encrypted file
3. Specify where to save the decrypted file
4. Enter the same password used during encryption
5. The original file will be restored

**Example:**
```
Enter the path of the encrypted file: document.enc
Enter the path for the decrypted file: document_decrypted.txt
Enter decryption password: ********
```

## Project Structure

```
Cryptography/
├── src/
│   ├── Main.java           # Entry point with CLI interface
│   ├── FileEncryptor.java  # Handles file encryption
│   ├── FileDecryptor.java  # Handles file decryption
│   └── CryptoUtils.java    # Cryptographic utilities (key derivation, salt generation)
├── .gitignore
└── Cryptography.iml
```

## Security Features

- **PBKDF2 Key Derivation**: Converts passwords to encryption keys with 65,536 iterations, making brute-force attacks computationally expensive
- **Random Salt**: Each encryption generates a unique salt, ensuring the same password produces different keys
- **Random IV**: Ensures identical files encrypted with the same password produce different ciphertext
- **Secure Password Handling**: Uses `char[]` instead of `String` and clears passwords from memory after use
- **Hidden Password Input**: Uses Console API to hide password input when available

## Technical Details

- **Algorithm**: AES (Advanced Encryption Standard)
- **Key Size**: 256 bits
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS5
- **Key Derivation**: PBKDF2 with HMAC-SHA256
- **Iterations**: 65,536
- **Salt Size**: 16 bytes (128 bits)
- **IV Size**: 16 bytes (128 bits)

## File Format

Encrypted files have the following structure:

```
[16 bytes: Salt][16 bytes: IV][Encrypted Content]
```

The salt and IV must be stored with the encrypted data to enable decryption.

## Error Handling

The tool provides clear error messages for common issues:
- Incorrect password (BadPaddingException)
- Missing or corrupted files
- Invalid encrypted file format
- File I/O errors

## Limitations

- Password strength depends on user choice (use strong passwords!)
- Files must fit available disk space (encrypted files are slightly larger)
- Console password hiding may not work in all IDEs (password will be visible)

## Contributing

Feel free to submit issues or pull requests for improvements.

## License

This project is provided as-is for educational and practical use.

## Notes

⚠️ **Important**: Always remember your encryption password! There is no way to recover an encrypted file without the correct password.

🔒 **Security Tip**: Use strong, unique passwords for important files. Consider using a password manager.
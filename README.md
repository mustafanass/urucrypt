# UruCrypt File Encryption Tool

UruCrypt is a secure file encryption and decryption tool designed with strong security practices and modern cryptographic standards. It provides robust file encryption with careful attention to secure memory handling and protection of sensitive data.

## Features

- AES-256-GCM encryption for strong security and authentication
- Secure memory handling for sensitive data
- Password-based key derivation using Argon2 (new update)
- Progress tracking during operations
- Configurable logging system
- Protection against timing attacks
- Secure cleanup of sensitive data
- Command-line interface for easy integration

## Technical Architecture

### Core Components

1. **Encryption Module (`encryption.c`)**
   - Implements file encryption/decryption using AES-256-GCM
   - Handles chunked file processing for large files
   - Manages cryptographic parameters (salt, IV, authentication tags)

2. **Key Management (`key_management.c`)**
   - Handles secure key derivation using PBKDF2
   - Manages password verification
   - Generates cryptographic random numbers
   - Implements secure key storage

3. **Secure Memory (`secure_memory.c`)**
   - Provides secure memory allocation and deallocation
   - Implements memory locking to prevent swapping
   - Ensures secure memory wiping
   - Includes canary values for overflow detection

4. **Error Handling (`error_handling.c`)**
   - Centralized error management system
   - Detailed error messages and codes
   - Thread-safe error handling

5. **Logging System (`logging.c`)**
   - Configurable log levels (ERROR, WARN, INFO)
   - Timestamp-based logging
   - Progress tracking
   - Secure logging of sensitive operations

6. **Utilities (`utils.c`)**
   - File validation and handling
   - Progress display
   - Secure string comparison
   - Hexadecimal conversion utilities

### Security Mechanisms

#### Cryptographic Design
- **Algorithm**: AES-256-GCM
  - Provides both confidentiality and authenticity
  - Authentication tags prevent tampering
  - Secure against padding oracle attacks

#### Key Derivation
- **Argon2 (new update from PBKDF2)**
   - Memory-hard algorithm for robust protection against GPU-based attacks
   - Configurable parameters for time, memory, and parallelism
   - Unique salt for each encryption
   - Provides both key derivation and verification capabilities

#### Memory Protection
- Secure memory allocation with:
  - Zero initialization
  - Memory locking
  - Protection against core dumps
  - Canary values for overflow detection
- Immediate secure cleanup after use

#### Anti-Timing Attack Measures
- Constant-time comparisons for sensitive data
- Secure string comparison implementation
- Consistent operation timing regardless of input

## Code Structure

```
urucrypt/
├── include/
│   ├── encryption.h
│   ├── key_management.h
│   ├── secure_memory.h
│   ├── error_handling.h
│   ├── logging.h
│   └── utils.h
├── src/
│   ├── encryption.c
│   ├── key_management.c
│   ├── secure_memory.c
│   ├── error_handling.c
│   ├── logging.c
│   └── utils.c
└── main.c
```

## Technology Choices

1. **OpenSSL**
   - Industry-standard cryptographic library
   - Well-audited implementation
   - Regular security updates
   - Comprehensive cryptographic functions

2. **C Language**
   - Direct memory management control
   - High performance
   - Low-level security controls
   - System-level integration capabilities

3. **File Chunking**
   - Enables handling of large files
   - Memory-efficient processing
   - Progress tracking capability
   - Resumable operations

## Build and Installation

```bash
# Clone the repository
git clone https://github.com/mustafanass/urucrypt

# Navigate to the directory
cd urucrypt

# Build the project
make

# Clean the old project (optional)
make clean

# Install (optional)
sudo make install
```

### Dependencies
- OpenSSL development libraries
- Argon2 development libraries
- C compiler (GCC or Clang)
- Make build system

## Usage

### Basic Usage

```bash
# Encryption
urucrypt -e input_file output_file passphrase [-l log_level]

# Decryption
urucrypt -d input_file output_file passphrase [-l log_level]
```

### Options
- `-e`: Encrypt mode
- `-d`: Decrypt mode
- `-l`: Log level (0=errors only, 1=warnings, 2=info)

### Examples

```bash
# Encrypt a file
urucrypt -e secret.txt secret.enc MySecurePassword

# Decrypt a file
urucrypt -d secret.enc decrypted.txt MySecurePassword

# Encrypt with minimal logging
urucrypt -e secret.txt secret.enc MySecurePassword -l 0
```

## Security Considerations

1. **Password Strength**
   - Minimum 8 characters
   - Mix of characters recommended
   - No maximum length limit

2. **File Safety**
   - Original files are preserved
   - No overwriting of existing files
   - Secure cleanup on failures

3. **Memory Security**
   - Sensitive data kept in locked memory
   - Immediate cleanup after use
   - Protection against memory dumps

4. **Error Handling**
   - Secure error messages
   - No leakage of sensitive data
   - Proper cleanup on errors

## Logging System

The logging system provides three levels of detail:
- **0 (ERROR)**: Critical errors only
- **1 (WARN)**: Warnings and errors
- **2 (INFO)**: Full information (default)

Logs are written to `urucrypt.log` in the current directory.

## Error Codes

- `ERROR_NONE`: No error
- `ERROR_FILE_OPEN`: File access error
- `ERROR_FILE_READ`: File read error
- `ERROR_FILE_WRITE`: File write error
- `ERROR_MEMORY`: Memory allocation error
- `ERROR_CRYPTO`: Cryptographic operation error
- `ERROR_INVALID_INPUT`: Invalid input parameters
- `ERROR_AUTH_FAILED`: Authentication failure

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Author

Build and Developed by Mustafa Naseer

This project is intended for development and testing purposes. For production use, please ensure proper configuration of external services and security measures.

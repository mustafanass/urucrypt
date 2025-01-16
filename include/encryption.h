#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "crypto_params.h"

// Define OpenSSL block length if not defined
#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32
#endif

// Encryption functions
int encrypt_file(const char *input_file, const char *output_file, const char *passphrase);
int decrypt_file(const char *input_file, const char *output_file, const char *passphrase);

#endif
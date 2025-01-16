#ifndef CRYPTO_PARAMS_H
#define CRYPTO_PARAMS_H

#include <stddef.h>

/* Cryptographic constants */
#define SALT_SIZE 32
#define IV_SIZE 16
#define KEY_SIZE 32
#define PASS_HASH_SIZE 32
#define CHUNK_SIZE 4096
#define MAX_PASSPHRASE_SIZE 256
#define KDF_ITERATIONS 100000

/* Structure to hold encryption parameters */
typedef struct CryptoParams {
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char pass_hash[PASS_HASH_SIZE];
} CryptoParams;

#endif /* CRYPTO_PARAMS_H */
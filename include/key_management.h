#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include "crypto_params.h"

/* Key management function prototypes */
void generate_random_bytes(unsigned char *buffer, size_t size);
void derive_key(const char *passphrase, CryptoParams *params);
int verify_passphrase(const char *passphrase, const CryptoParams *params);
void secure_erase(void *ptr, size_t size);

#endif /* KEY_MANAGEMENT_H */
/*
 * Copyright (C) 2025 Mustafa Naseer
 *
 * This file is part of UruCrypt encryption application.
 *
 * UruCrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 3 of the License.
 *
 * UruCrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with UruCrypt. If not, see <http://www.gnu.org/licenses/>.
 */

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

#endif 

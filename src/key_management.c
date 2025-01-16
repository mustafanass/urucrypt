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

#include "../include/key_management.h"
#include "../include/error_handling.h"
#include "../include/logging.h"
#include "../include/secure_memory.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Securely generates random bytes using OpenSSL's CSPRNG
void generate_random_bytes(unsigned char *buffer, size_t size) {
    // Validate input parameters
    if (!buffer || size == 0) {
        set_error(ERROR_INVALID_INPUT, "Invalid buffer for random bytes");
        return;
    }

    // Ensure system has enough entropy
    if (!RAND_status()) {
        set_error(ERROR_CRYPTO, "Insufficient entropy");
        return;
    }

    // Use secure memory for temporary storage
    void *secure_buffer = secure_malloc(size, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    if (!secure_buffer) {
        set_error(ERROR_MEMORY, "Failed to allocate secure buffer");
        return;
    }

    // Generate random bytes using OpenSSL
    if (RAND_bytes(secure_buffer, size) != 1) {
        set_error(ERROR_CRYPTO, "Failed to generate random bytes");
        log_error("Critical: Random number generation failed");
        secure_erase(secure_buffer, size);
        secure_free(secure_buffer);
        return;
    }

    // Copy to output buffer and clean up
    secure_memcpy(buffer, size, secure_buffer, size);
    secure_erase(secure_buffer, size);
    secure_free(secure_buffer);
}

// Derives encryption key and verification hash from passphrase using PBKDF2
void derive_key(const char *passphrase, CryptoParams *params) {
    // Validate input parameters
    if (!passphrase || !params) {
        set_error(ERROR_INVALID_INPUT, "Invalid parameters for key derivation");
        return;
    }

    // Check passphrase length requirements
    size_t pass_len = strlen(passphrase);
    if (pass_len < 8 || pass_len > MAX_PASSPHRASE_SIZE) {
        set_error(ERROR_INVALID_INPUT, "Invalid passphrase length");
        return;
    }

    // Allocate secure memory for temporary storage
    void *temp_key = secure_malloc(KEY_SIZE, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    void *temp_hash = secure_malloc(PASS_HASH_SIZE, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    if (!temp_key || !temp_hash) {
        secure_free(temp_key);
        secure_free(temp_hash);
        set_error(ERROR_MEMORY, "Failed to allocate secure buffers");
        return;
    }

    // Store passphrase in secure memory
    void *secure_pass = secure_malloc(pass_len + 1, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    if (!secure_pass) {
        secure_free(temp_key);
        secure_free(temp_hash);
        set_error(ERROR_MEMORY, "Failed to allocate secure passphrase buffer");
        return;
    }

    secure_memcpy(secure_pass, pass_len + 1, passphrase, pass_len);
    ((char *)secure_pass)[pass_len] = '\0';

    // Generate encryption key using PBKDF2
    if (!PKCS5_PBKDF2_HMAC(secure_pass, pass_len, params->salt, SALT_SIZE,
                           KDF_ITERATIONS, EVP_sha256(), KEY_SIZE, temp_key)) {
        set_error(ERROR_CRYPTO, "Failed to derive key");
        log_error("Critical: Key derivation operation failed");
        goto cleanup;
    }

    // Generate verification hash using PBKDF2
    if (!PKCS5_PBKDF2_HMAC(secure_pass, pass_len, params->salt, SALT_SIZE,
                           KDF_ITERATIONS, EVP_sha256(), PASS_HASH_SIZE,
                           temp_hash)) {
        set_error(ERROR_CRYPTO, "Failed to generate password verification hash");
        log_error("Critical: Verification hash generation failed");
        goto cleanup;
    }

    // Store results and verify they were copied correctly
    memcpy(params->key, temp_key, KEY_SIZE);
    memcpy(params->pass_hash, temp_hash, PASS_HASH_SIZE);

    if (memcmp(params->key, temp_key, KEY_SIZE) != 0 ||
        memcmp(params->pass_hash, temp_hash, PASS_HASH_SIZE) != 0) {
        log_error("Critical: Key/hash storage verification failed");
        goto cleanup;
    }

cleanup:
    // Securely erase and free all temporary buffers
    if (secure_pass) {
        secure_erase(secure_pass, pass_len + 1);
        secure_free(secure_pass);
    }
    if (temp_key) {
        secure_erase(temp_key, KEY_SIZE);
        secure_free(temp_key);
    }
    if (temp_hash) {
        secure_erase(temp_hash, PASS_HASH_SIZE);
        secure_free(temp_hash);
    }
}

// Verifies password against stored hash using constant-time comparison
int verify_passphrase(const char *passphrase, const CryptoParams *params) {
    // Validate input parameters
    if (!passphrase || !params) {
        set_error(ERROR_INVALID_INPUT, "Invalid parameters for password verification");
        return 0;
    }

    // Check passphrase length requirements
    size_t pass_len = strlen(passphrase);
    if (pass_len < 8 || pass_len > MAX_PASSPHRASE_SIZE) {
        set_error(ERROR_INVALID_INPUT, "Invalid passphrase length");
        return 0;
    }

    // Allocate secure memory for verification
    int result = 0;
    void *test_hash = secure_malloc(PASS_HASH_SIZE, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    if (!test_hash) {
        set_error(ERROR_MEMORY, "Failed to allocate secure hash buffer");
        return 0;
    }

    void *secure_pass = secure_malloc(pass_len + 1, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK);
    if (!secure_pass) {
        secure_free(test_hash);
        set_error(ERROR_MEMORY, "Failed to allocate secure passphrase buffer");
        return 0;
    }

    // Copy passphrase to secure memory
    secure_memcpy(secure_pass, pass_len + 1, passphrase, pass_len);
    ((char *)secure_pass)[pass_len] = '\0';

    // Generate verification hash
    if (!PKCS5_PBKDF2_HMAC(secure_pass, pass_len, params->salt, SALT_SIZE,
                           KDF_ITERATIONS, EVP_sha256(), PASS_HASH_SIZE,
                           test_hash)) {
        set_error(ERROR_CRYPTO, "Failed to generate verification hash");
        log_error("Critical: Password verification hash generation failed");
        goto cleanup;
    }

    // Constant-time comparison of hashes
    result = CRYPTO_memcmp(test_hash, params->pass_hash, PASS_HASH_SIZE) == 0;

cleanup:
    // Securely erase and free temporary buffers
    if (test_hash) {
        secure_erase(test_hash, PASS_HASH_SIZE);
        secure_free(test_hash);
    }
    if (secure_pass) {
        secure_erase(secure_pass, pass_len + 1);
        secure_free(secure_pass);
    }

    if (!result) {
        set_error(ERROR_AUTH_FAILED, "Password verification failed");
    }

    return result;
}

// Securely erases memory using OpenSSL's secure memory cleansing function
void secure_erase(void *ptr, size_t size) {
    if (ptr) {
        OPENSSL_cleanse(ptr, size);
    }
}
#include "../include/encryption.h"
#include "../include/error_handling.h"
#include "../include/key_management.h"
#include "../include/secure_memory.h"
#include "../include/logging.h"
#include "../include/utils.h"
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

int encrypt_file(const char *input_file, const char *output_file, const char *passphrase) {
    // Initialize variables and log start
    char start_msg[512];
    snprintf(start_msg, sizeof(start_msg), "Starting encryption: %s -> %s", input_file, output_file);
    log_message(start_msg);

    // Validate inputs and open files
    if (!validate_input_files(input_file, output_file)) {
        log_error("Input/output file validation failed");
        return 0;
    }

    if (!passphrase || strlen(passphrase) < 8) {
        log_error("Invalid passphrase: must be at least 8 characters");
        return 0;
    }

    FILE *ifp = fopen(input_file, "rb");
    FILE *ofp = fopen(output_file, "wb");
    if (!ifp || !ofp) {
        log_error("Failed to open input or output file");
        if (ifp) fclose(ifp);
        return 0;
    }

    // Allocate secure memory for crypto parameters
    void *params_mem = secure_malloc(sizeof(CryptoParams), 
                                   SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK | SECURE_MEM_NO_DUMP);
    if (!params_mem) {
        log_error("Failed to allocate secure memory");
        fclose(ifp);
        fclose(ofp);
        return 0;
    }

    CryptoParams *params = (CryptoParams *)params_mem;

    // Generate cryptographic parameters and derive key
    generate_random_bytes(params->salt, SALT_SIZE);
    generate_random_bytes(params->iv, IV_SIZE);
    derive_key(passphrase, params);

    // Write file header (hash, salt, IV)
    if (fwrite(params->pass_hash, 1, PASS_HASH_SIZE, ofp) != PASS_HASH_SIZE ||
        fwrite(params->salt, 1, SALT_SIZE, ofp) != SALT_SIZE ||
        fwrite(params->iv, 1, IV_SIZE, ofp) != IV_SIZE) {
        log_error("Failed to write crypto parameters");
        secure_free(params_mem);
        fclose(ifp);
        fclose(ofp);
        return 0;
    }

    // Initialize encryption context (AES-256-GCM)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, params->key, params->iv)) {
        log_error("Encryption initialization failed");
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        secure_free(params_mem);
        fclose(ifp);
        fclose(ofp);
        return 0;
    }

    // Allocate secure memory for encryption buffers
    void *in_buffer = secure_malloc(CHUNK_SIZE, SECURE_MEM_LOCK);
    void *out_buffer = secure_malloc(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH, SECURE_MEM_LOCK);
    if (!in_buffer || !out_buffer) {
        log_error("Failed to allocate encryption buffers");
        EVP_CIPHER_CTX_free(ctx);
        secure_free(params_mem);
        secure_free(in_buffer);
        secure_free(out_buffer);
        fclose(ifp);
        fclose(ofp);
        return 0;
    }

    // Process file in chunks with progress tracking
    size_t bytes_read;
    int outlen, final_len;
    size_t total_bytes_processed = 0;
    size_t file_size = get_file_size(input_file);
    const size_t progress_threshold = file_size / 4;
    size_t next_progress_mark = progress_threshold;

    // Main encryption loop
    while ((bytes_read = fread(in_buffer, 1, CHUNK_SIZE, ifp)) > 0) {
        if (!EVP_EncryptUpdate(ctx, out_buffer, &outlen, in_buffer, bytes_read)) {
            log_error("Encryption update failed");
            goto cleanup;
        }

        if (fwrite(out_buffer, 1, outlen, ofp) != (size_t)outlen) {
            log_error("Failed to write encrypted data");
            goto cleanup;
        }

        // Update progress (25%, 50%, 75%, 100%)
        total_bytes_processed += bytes_read;
        if (total_bytes_processed >= next_progress_mark || total_bytes_processed == file_size) {
            char progress_msg[100];
            int progress_percent = (int)((total_bytes_processed * 100) / file_size);
            snprintf(progress_msg, sizeof(progress_msg), "Encryption progress: %d%%", progress_percent);
            log_message(progress_msg);
            next_progress_mark += progress_threshold;
        }
    }

    // Finalize encryption and write authentication tag
    if (!EVP_EncryptFinal_ex(ctx, out_buffer, &final_len) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_buffer + final_len)) {
        log_error("Encryption finalization failed");
        goto cleanup;
    }

    if (fwrite(out_buffer, 1, final_len + 16, ofp) != (size_t)(final_len + 16)) {
        log_error("Failed to write final block");
        goto cleanup;
    }

    log_message("Encryption completed successfully");
    EVP_CIPHER_CTX_free(ctx);
    secure_free(params_mem);
    secure_free(in_buffer);
    secure_free(out_buffer);
    fclose(ifp);
    fclose(ofp);
    return 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    secure_free(params_mem);
    secure_free(in_buffer);
    secure_free(out_buffer);
    fclose(ifp);
    fclose(ofp);
    return 0;
}

int decrypt_file(const char *input_file, const char *output_file, const char *passphrase) {
    // Initialize variables and resources
    char start_msg[512];
    snprintf(start_msg, sizeof(start_msg), "Starting decryption: %s -> %s", input_file, output_file);
    log_message(start_msg);

    void *params_mem = NULL;
    void *in_buffer = NULL;
    void *out_buffer = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *ifp = NULL;
    FILE *ofp = NULL;
    int result = 0;

    // Validate inputs
    if (!passphrase || strlen(passphrase) < 8) {
        log_error("Invalid passphrase: must be at least 8 characters");
        set_error(ERROR_INVALID_INPUT, "Invalid passphrase length");
        return 0;
    }

    // Check if file is large enough to be valid
    size_t input_size = get_file_size(input_file);
    size_t min_size = (size_t)(PASS_HASH_SIZE + SALT_SIZE + IV_SIZE + 16);
    if (input_size <= min_size) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                "Invalid encrypted file (size: %zu, minimum required: %zu)", 
                input_size, min_size);
        log_error(error_msg);
        set_error(ERROR_INVALID_INPUT, "Input file is not a valid encrypted file");
        return 0;
    }

    // Open input file and allocate secure memory
    ifp = fopen(input_file, "rb");
    if (!ifp) {
        log_error("Cannot open input file for reading");
        set_error(ERROR_FILE_OPEN, "Cannot open input file");
        return 0;
    }

    params_mem = secure_malloc(sizeof(CryptoParams),
                             SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK |
                             SECURE_MEM_NO_DUMP);
    if (!params_mem) {
        log_error("Failed to allocate secure memory for parameters");
        set_error(ERROR_MEMORY, "Memory allocation failed");
        goto cleanup;
    }
    CryptoParams *params = (CryptoParams *)params_mem;

    // Read and verify crypto parameters
    if (fread(params->pass_hash, 1, PASS_HASH_SIZE, ifp) != PASS_HASH_SIZE ||
        fread(params->salt, 1, SALT_SIZE, ifp) != SALT_SIZE ||
        fread(params->iv, 1, IV_SIZE, ifp) != IV_SIZE) {
        log_error("Failed to read crypto parameters from file");
        set_error(ERROR_FILE_READ, "Failed to read file header");
        goto cleanup;
    }

    // Verify password before proceeding
    derive_key(passphrase, params);
    if (!verify_passphrase(passphrase, params)) {
        log_error("Invalid password provided");
        set_error(ERROR_AUTH_FAILED, "Incorrect password");
        goto cleanup;
    }

    // Initialize decryption context (AES-256-GCM)
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, params->key, params->iv)) {
        log_error("Failed to initialize decryption");
        set_error(ERROR_CRYPTO, "Decryption initialization failed");
        goto cleanup;
    }

    // Allocate secure buffers for decryption
    in_buffer = secure_malloc(CHUNK_SIZE, SECURE_MEM_LOCK);
    out_buffer = secure_malloc(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH, SECURE_MEM_LOCK);
    if (!in_buffer || !out_buffer) {
        log_error("Failed to allocate buffers");
        set_error(ERROR_MEMORY, "Memory allocation failed");
        goto cleanup;
    }

    ofp = fopen(output_file, "wb");
    if (!ofp) {
        log_error("Failed to create output file");
        set_error(ERROR_FILE_OPEN, "Cannot create output file");
        goto cleanup;
    }

    // Process encrypted data in chunks
    size_t total_read = PASS_HASH_SIZE + SALT_SIZE + IV_SIZE;
    size_t bytes_to_read = input_size - total_read - 16;  // -16 for auth tag
    size_t total_bytes = bytes_to_read;
    int outlen;
    const size_t progress_threshold = bytes_to_read / 4;
    size_t next_progress_mark = progress_threshold;

    // Main decryption loop
    while (total_read < input_size - 16) {
        size_t current_chunk = (bytes_to_read > CHUNK_SIZE) ? CHUNK_SIZE : bytes_to_read;
        size_t bytes_read = fread(in_buffer, 1, current_chunk, ifp);

        if (bytes_read == 0) break;

        if (!EVP_DecryptUpdate(ctx, out_buffer, &outlen, in_buffer, bytes_read)) {
            log_error("Decryption update failed");
            set_error(ERROR_CRYPTO, "Decryption failed");
            goto cleanup;
        }

        if (fwrite(out_buffer, 1, outlen, ofp) != (size_t)outlen) {
            log_error("Failed to write decrypted data");
            set_error(ERROR_FILE_WRITE, "Write failed");
            goto cleanup;
        }

        total_read += bytes_read;
        bytes_to_read -= bytes_read;

        // Update progress (25%, 50%, 75%, 100%)
        size_t bytes_processed = total_bytes - bytes_to_read;
        if (bytes_processed >= next_progress_mark || bytes_processed == total_bytes) {
            int progress_percent = (int)((bytes_processed * 100) / total_bytes);
            char progress_msg[100];
            snprintf(progress_msg, sizeof(progress_msg), "Decryption progress: %d%%", progress_percent);
            log_message(progress_msg);
            next_progress_mark += progress_threshold;
        }
    }

    // Verify data integrity with auth tag
    unsigned char tag[16];
    if (fread(tag, 1, 16, ifp) != 16) {
        log_error("Failed to read authentication tag");
        set_error(ERROR_FILE_READ, "Failed to read tag");
        goto cleanup;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        log_error("Failed to set authentication tag");
        set_error(ERROR_CRYPTO, "Tag verification failed");
        goto cleanup;
    }

    // Finalize decryption and verify integrity
    int final_len;
    if (!EVP_DecryptFinal_ex(ctx, out_buffer, &final_len)) {
        log_error("Data integrity check failed");
        set_error(ERROR_AUTH_FAILED, "Data integrity check failed");
        goto cleanup;
    }

    if (final_len > 0 && fwrite(out_buffer, 1, final_len, ofp) != (size_t)final_len) {
        log_error("Failed to write final block");
        set_error(ERROR_FILE_WRITE, "Write failed");
        goto cleanup;
    }

    log_message("Decryption completed successfully");
    result = 1;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in_buffer) secure_free(in_buffer);
    if (out_buffer) secure_free(out_buffer);
    if (params_mem) secure_free(params_mem);
    if (ifp) fclose(ifp);
    if (ofp) {
        fclose(ofp);
        if (!result && output_file) {
            log_message("Removing failed output file");
            unlink(output_file);
        }
    }

    if (!result) {
        log_error("Decryption failed - OpenSSL errors:");
    }

    return result;
}
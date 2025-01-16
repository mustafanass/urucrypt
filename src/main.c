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

#include "../include/encryption.h"
#include "../include/error_handling.h"
#include "../include/logging.h"
#include "../include/secure_memory.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

// Display program usage information and command-line options
void print_usage(const char *program_name) {
  fprintf(
      stderr,
      "Usage: %s [-e|-d] input_file output_file passphrase [-l log_level]\n",
      program_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -e            : Encrypt mode\n");
  fprintf(stderr, "  -d            : decrypt mode\n");
  fprintf(stderr, "  -l log_level  : Set log level (0=errors only, 1=warnings, "
                  "2=info   (Optional))\n");
  fprintf(stderr, "                  Default is 2 (info)\n");
}

int main(int argc, char *argv[]) {
  // Validate command-line arguments
  if (argc < 5 || argc > 7) {
    print_usage(argv[0]);
    return 1;
  }

  // Extract basic command-line parameters
  const char *mode = argv[1];
  const char *input_file = argv[2];
  const char *output_file = argv[3];

  // Initialize logging system with default settings
  init_logging("urucrypt.log");
  set_log_level(LOG_LEVEL_INFO);

  // Process optional log level parameter
  for (int i = 5; i < argc; i++) {
    if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      int level = atoi(argv[i + 1]);
      if (level >= 0 && level <= 2) {
        set_log_level((LogLevel)level);
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "Log level set to %d", level);
        log_message(log_msg);
      } else {
        fprintf(stderr, "Invalid log level. Using default (2)\n");
      }
      break;
    }
  }

  // Securely handle passphrase
  size_t pass_len = strlen(argv[4]);
  void *secure_passphrase =
      secure_malloc(pass_len + 1, SECURE_MEM_ZERO_INIT | SECURE_MEM_LOCK |
                                      SECURE_MEM_NO_DUMP);
  if (!secure_passphrase) {
    fprintf(stderr, "Error: Failed to allocate secure memory for passphrase\n");
    return 1;
  }

  // Copy passphrase to secure memory and clear original
  if (secure_memcpy(secure_passphrase, pass_len + 1, argv[4], pass_len) != 0) {
    fprintf(stderr, "Error: Failed to copy passphrase to secure memory\n");
    secure_free(secure_passphrase);
    return 1;
  }
  secure_memzero(argv[4], pass_len); // Erase passphrase from command line

  // Initialize cryptographic subsystem
  OpenSSL_add_all_algorithms();
  clear_error();

  // Perform encryption or decryption based on mode
  int success = 0;
  if (strcmp(mode, "-e") == 0) {
    success = encrypt_file(input_file, output_file, secure_passphrase);
  } else if (strcmp(mode, "-d") == 0) {
    success = decrypt_file(input_file, output_file, secure_passphrase);
  } else {
    log_error("Invalid mode specified");
    fprintf(stderr,
            "Error: Invalid mode. Use -e for encrypt or -d for decrypt\n");
    secure_free(secure_passphrase);
    return 1;
  }

  // Clean up and handle results
  EVP_cleanup();
  secure_free(secure_passphrase);

  if (!success) {
    const char *error_msg = get_error_message();
    ErrorCode error_code = get_last_error();
    log_error(error_msg);
    fprintf(stderr, "Operation failed: %s (Error code: %d)\n", error_msg,
            error_code);
    close_logging();
    return 1;
  }

  close_logging();
  printf("Operation completed successfully\n");
  return 0;
}
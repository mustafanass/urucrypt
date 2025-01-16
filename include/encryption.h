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
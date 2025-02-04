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

#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include "crypto_params.h"

/* Key management function prototypes */
void generate_random_bytes(unsigned char *buffer, size_t size);
void derive_key(const char *passphrase, CryptoParams *params);
int verify_passphrase(const char *passphrase, const CryptoParams *params);
void secure_erase(void *ptr, size_t size);

#endif

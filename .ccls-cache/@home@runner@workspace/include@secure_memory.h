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

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

// Memory allocation flags
#define SECURE_MEM_ZERO_INIT 0x01 // Zero initialize memory
#define SECURE_MEM_LOCK 0x02      // Lock memory in RAM (prevent swapping)
#define SECURE_MEM_NO_DUMP 0x04 // Prevent memory from being included in core dumps

// Secure memory structure with canaries and size information
typedef struct {
  size_t size;
  uint32_t canary_top;
  uint8_t data[];
} SecureMemory;

// Secure memory allocation functions
void *secure_malloc(size_t size, uint32_t flags);
void *secure_calloc(size_t nmemb, size_t size, uint32_t flags);
void *secure_realloc(void *ptr, size_t new_size, uint32_t flags);
void secure_free(void *ptr);

// Memory protection functions
int secure_mlock(void *ptr);
int secure_munlock(void *ptr);
void secure_memzero(void *ptr, size_t size);

// Bounds checking functions
int secure_memcpy(void *dest, size_t dest_size, const void *src, size_t count);
int secure_memset(void *dest, size_t dest_size, int value, size_t count);

// Memory validation functions
int validate_secure_memory(void *ptr);
size_t get_secure_memory_size(void *ptr);

#endif
#include "../include/secure_memory.h"
#include "../include/error_handling.h"
#include "../include/logging.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CANARY_VALUE 0xDEADBEEF
#define ALIGNMENT 16
#define PAGE_SIZE 4096

/*
NOTE: This is a simplified version of memory management used to make it as easy
as possible to understand the code. It uses canaries, memory protection flags,
and secure memory functions to provide a basic level of memory safety. This is
not a complete or fully robust memory management solution, but it aims to
demonstrate key concepts and provide a starting point for more complex
implementations.
*/

// Helper function to align size
static size_t align_size(size_t size) {
  return (size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
}

// Helper function to get actual allocation size including metadata
static size_t get_allocation_size(size_t requested_size) {
  size_t base_size =
      align_size(sizeof(SecureMemory) + requested_size + sizeof(uint32_t));
  return align_size(base_size);
}

void *secure_malloc(size_t size, uint32_t flags) {
  if (size == 0 || size > SIZE_MAX - sizeof(SecureMemory) - sizeof(uint32_t)) {
    set_error(ERROR_MEMORY, "Invalid allocation size");
    return NULL;
  }

  // Calculate total size needed including metadata
  size_t total_size = get_allocation_size(size);

  // Use posix_memalign for aligned allocation
  void *base_ptr;
  if (posix_memalign(&base_ptr, ALIGNMENT, total_size) != 0) {
    set_error(ERROR_MEMORY, "Memory allocation failed");
    return NULL;
  }

  // Initialize SecureMemory structure
  SecureMemory *secure_ptr = (SecureMemory *)base_ptr;
  secure_ptr->size = size;
  secure_ptr->canary_top = CANARY_VALUE;

  // Set bottom canary
  uint32_t *bottom_canary = (uint32_t *)((uint8_t *)secure_ptr->data + size);
  *bottom_canary = CANARY_VALUE;

  // Apply memory protection flags
  if (flags & SECURE_MEM_LOCK) {
    if (mlock(secure_ptr->data, size) != 0) {
      log_error("Failed to lock memory pages");
    }
  }

  if (flags & SECURE_MEM_ZERO_INIT) {
    explicit_bzero(secure_ptr->data, size);
  }

  if (flags & SECURE_MEM_NO_DUMP) {
    if (madvise(secure_ptr->data, size, MADV_DONTDUMP) != 0) {
      log_message("madvise with MADV_DONTDUMP is not supported. Skipping...");
    }
  }

  return secure_ptr->data;
}

void secure_free(void *ptr) {
  if (!ptr)
    return;

  // Get the base pointer from the data pointer
  SecureMemory *secure_ptr =
      (SecureMemory *)((uint8_t *)ptr - offsetof(SecureMemory, data));

  // Validate memory before freeing
  if (!validate_secure_memory(ptr)) {
    log_error("Memory corruption detected during free");
    abort();
  }

  // Secure cleanup
  size_t total_size = get_allocation_size(secure_ptr->size);

  // First, unlock if it was locked
  munlock(secure_ptr->data, secure_ptr->size);

  // Zero all memory including metadata
  explicit_bzero(secure_ptr, total_size);

  // Finally free the memory
  free(secure_ptr);
}

int validate_secure_memory(void *ptr) {
  if (!ptr)
    return 0;

  SecureMemory *secure_ptr =
      (SecureMemory *)((uint8_t *)ptr - offsetof(SecureMemory, data));

  // Check top canary
  if (secure_ptr->canary_top != CANARY_VALUE) {
    return 0;
  }

  // Check bottom canary
  uint32_t *bottom_canary = (uint32_t *)((uint8_t *)ptr + secure_ptr->size);
  if (*bottom_canary != CANARY_VALUE) {
    return 0;
  }

  return 1;
}

int secure_memcpy(void *dest, size_t dest_size, const void *src, size_t count) {
  if (!dest || !src) {
    set_error(ERROR_INVALID_INPUT, "NULL pointer in secure_memcpy");
    return -1;
  }

  // Validate destination buffer
  if (!validate_secure_memory(dest)) {
    set_error(ERROR_MEMORY, "Invalid destination buffer in secure_memcpy");
    return -1;
  }

  // Check bounds
  if (count > dest_size) {
    set_error(ERROR_MEMORY, "Buffer overflow attempted in secure_memcpy");
    return -1;
  }

  // Perform the copy
  memcpy(dest, src, count);
  return 0;
}

void secure_memzero(void *ptr, size_t size) {
  if (!ptr)
    return;

  // Use volatile pointer to prevent optimization
  volatile unsigned char *volatile p = ptr;
  while (size--) {
    *p++ = 0;
  }

  // Additional memory barrier for extra security
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

size_t get_secure_memory_size(void *ptr) {
  if (!ptr || !validate_secure_memory(ptr)) {
    return 0;
  }

  SecureMemory *secure_ptr =
      (SecureMemory *)((uint8_t *)ptr - offsetof(SecureMemory, data));
  return secure_ptr->size;
}
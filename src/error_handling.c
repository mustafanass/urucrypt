#include "../include/error_handling.h"
#include "../include/secure_memory.h"
#include <stdio.h>
#include <string.h>

// Maximum length for error messages
#define MAX_ERROR_MESSAGE_LENGTH 256

// Structure to store error information
typedef struct {
  ErrorCode code;
  char message[MAX_ERROR_MESSAGE_LENGTH];
} SecureError;

// Global error state
static SecureError current_error = {ERROR_NONE, ""};

// Sets the current error state with a code and optional message
void set_error(ErrorCode code, const char *message) {
  current_error.code = code;

  if (message) {
    // Copy message with bounds checking
    strncpy(current_error.message, message, MAX_ERROR_MESSAGE_LENGTH - 1);
    current_error.message[MAX_ERROR_MESSAGE_LENGTH - 1] = '\0';
  } else {
    current_error.message[0] = '\0';
  }
}

// Returns current error message or default message based on error code
const char *get_error_message(void) {
  if (current_error.message[0] == '\0') {
    // Return default message if no custom message was set
    switch (current_error.code) {
    case ERROR_NONE:
      return "No error";
    case ERROR_FILE_OPEN:
      return "File open error";
    case ERROR_FILE_READ:
      return "File read error";
    case ERROR_FILE_WRITE:
      return "File write error";
    case ERROR_MEMORY:
      return "Memory error";
    case ERROR_CRYPTO:
      return "Cryptographic error";
    case ERROR_INVALID_INPUT:
      return "Invalid input";
    case ERROR_AUTH_FAILED:
      return "Authentication failed";
    default:
      return "Unknown error";
    }
  }
  return current_error.message;
}

// Returns the current error code
ErrorCode get_last_error(void) { return current_error.code; }

// Resets error state to default values
void clear_error(void) {
  current_error.code = ERROR_NONE;
  current_error.message[0] = '\0';
}
#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

typedef enum {
  ERROR_NONE = 0,
  ERROR_FILE_OPEN,
  ERROR_FILE_READ,
  ERROR_FILE_WRITE,
  ERROR_MEMORY,
  ERROR_CRYPTO,
  ERROR_INVALID_INPUT,
  ERROR_AUTH_FAILED
} ErrorCode;

// Error handling functions
void set_error(ErrorCode code, const char *message);
const char *get_error_message(void);
ErrorCode get_last_error(void);
void clear_error(void);

#endif
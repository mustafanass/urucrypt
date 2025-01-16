#ifndef LOGGING_H
#define LOGGING_H

// Define log levels
typedef enum LogLevel {
  LOG_LEVEL_ERROR = 0,
  LOG_LEVEL_WARN = 1,
  LOG_LEVEL_INFO = 2
} LogLevel;

// Function declarations
void init_logging(const char *log_file_name);
void set_log_level(LogLevel level);
void log_message(const char *message);
void log_error(const char *error_message);
void log_warning(const char *warning_message);
void close_logging(void);

#endif
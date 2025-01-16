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

#include "../include/logging.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// Global logging state
static FILE *log_file = NULL;
static LogLevel current_log_level = LOG_LEVEL_INFO; // Default to INFO level

// Initialize logging system with specified file
void init_logging(const char *log_file_name) {
  log_file = fopen(log_file_name, "a"); // Append mode for continuous logging
  if (!log_file) {
    fprintf(stderr, "Failed to open log file: %s\n", log_file_name);
  }
}

// Internal function to write formatted log entries
static void write_log(LogLevel level, const char *prefix, const char *message) {
  if (!log_file || level > current_log_level)
    return;

  // Add timestamp to log entry
  time_t now = time(NULL);
  char *timestamp = ctime(&now);
  timestamp[24] = '\0'; // Remove newline from ctime output

  // Write formatted log entry and flush immediately
  fprintf(log_file, "[%s] %s: %s\n", timestamp, prefix, message);
  fflush(log_file);
}

// Set the minimum level for logging output
void set_log_level(LogLevel level) { current_log_level = level; }

// Log informational messages (filtered to reduce noise)
void log_message(const char *message) {
  // Only log important state changes and completion events
  if (strstr(message, "Starting") ||
      strstr(message, "completed successfully") ||
      strstr(message, "progress: 100%")) {
    write_log(LOG_LEVEL_INFO, "INFO", message);
  }
}

// Log error messages (always logged regardless of level)
void log_error(const char *error_message) {
  write_log(LOG_LEVEL_ERROR, "ERROR", error_message);
}

// Log warning messages (intermediate priority)
void log_warning(const char *warning_message) {
  write_log(LOG_LEVEL_WARN, "WARN", warning_message);
}

// Clean up logging system and close file
void close_logging(void) {
  if (log_file) {
    fclose(log_file);
    log_file = NULL;
  }
}
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
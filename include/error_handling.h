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
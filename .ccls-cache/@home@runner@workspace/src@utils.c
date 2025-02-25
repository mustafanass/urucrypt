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

#include "../include/utils.h"
#include "../include/error_handling.h"
#include "../include/secure_memory.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

// Validate input/output file paths and check file existence
int validate_input_files(const char *input_file, const char *output_file) {
  struct stat st;

  // Ensure input file exists
  if (stat(input_file, &st) != 0) {
    set_error(ERROR_INVALID_INPUT, "Input file does not exist");
    return 0;
  }

  // Prevent overwriting existing files
  if (stat(output_file, &st) == 0) {
    set_error(ERROR_INVALID_INPUT, "Output file already exists");
    return 0;
  }

  return 1;
}

// Get file size in bytes, returns 0 if file doesn't exist
size_t get_file_size(const char *filename) {
  struct stat st;
  if (stat(filename, &st) == 0) {
    return st.st_size;
  }
  return 0;
}
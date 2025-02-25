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

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

// Utility functions
int validate_input_files(const char *input_file, const char *output_file);
size_t get_file_size(const char *filename);

#endif
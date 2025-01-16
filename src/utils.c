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
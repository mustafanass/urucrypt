# Compiler to use
CC = gcc

# Compiler flags: enable all warnings and include the "include" directory
CFLAGS = -Wall -Wextra -I./include

# Linker flags: link with SSL, crypto, and argon2 libraries
LDFLAGS = -lssl -lcrypto -largon2

# Directories for source files, object files, and executable binary
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# List all C source files in the source directory
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
EXEC = $(BIN_DIR)/urucrypt

.PHONY: all clean
all: $(EXEC)

# Link object files to create the executable
$(EXEC): $(OBJS)
	@mkdir -p $(BIN_DIR)    # Create binary directory if it doesn't exist
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile C source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)    # Create object directory if it doesn't exist
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

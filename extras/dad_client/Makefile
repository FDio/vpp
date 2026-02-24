# Makefile for DAD client examples
#
# This builds the C structural example

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS =
TARGET = dad_client

# Source files
SRCS = dad_client.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "✓ Built $(TARGET)"

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "✓ Cleaned build artifacts"

# Run the example
run: $(TARGET)
	./$(TARGET)

# Install (copy to system path, requires root)
install: $(TARGET)
	@echo "Note: This is a structural example, installation not required"
	@echo "To run: ./$(TARGET)"

# Show help
help:
	@echo "DAD Client Example - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the C example (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  run      - Build and run the example"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Note: This C example is structural and demonstrates"
	@echo "      integration patterns. For a working implementation,"
	@echo "      see dad_client.py"

.PHONY: all clean run install help

CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Linker flags
LDFLAGS = -lpcap

# Source files
SRC = spectrum.c

# Output executable
TARGET = signal_spectrum

# Default rule
all: $(TARGET)

# Build rule
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Clean rule
clean:
	rm -f $(TARGET)

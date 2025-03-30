#!/bin/bash

# Define the subdirectory containing the source files
SUBDIR="signal-spectrum"

# Change to the subdirectory
cd "$SUBDIR" || { 
    echo "Directory $SUBDIR not found! Exiting." 
    exit 1; 
}

# Define the source file and target executable
SOURCE="spectrum.c"
TARGET="signal_spectrum"
MAKEFILE="Makefile"

# Check if the Makefile exists
if [ ! -f "$MAKEFILE" ]; then
    echo "Makefile not found!"
    exit 1
fi

# Build the program using make
echo "Compiling the program..."
make

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful. Running the program..."
    # Run the executable with sudo since it may require elevated privileges for packet capturing
    sudo ./"$TARGET"
else
    echo "Compilation failed. Please check for errors."
    exit 1
fi

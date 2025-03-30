#!/bin/bash

# Directory for the sniffer
SNIFF_DIR="sniff"

# Check if the directory exists
if [ ! -d "$SNIFF_DIR" ]; then
    echo "Directory $SNIFF_DIR does not exist."
    exit 1
fi

# Change to the directory
cd "$SNIFF_DIR"

# Check if interface argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

# Assign the provided interface to a variable
INTERFACE="$1"

# Start the packet sniffer using the provided interface
echo "Starting the packet sniffer on the interface: $INTERFACE"
sudo ./packet_sniffer "$INTERFACE" capture.pcap

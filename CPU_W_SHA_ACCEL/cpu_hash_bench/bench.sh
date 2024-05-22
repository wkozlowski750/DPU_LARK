#!/bin/bash

# Path to the compiled SHA-256 benchmark program
PROGRAM="./sha256_bench"

# Check if the program exists
if [ ! -f "$PROGRAM" ]; then
    echo "Program does not exist. Please compile the C program first."
    exit 1
fi

# Start at 64 bytes (2^6) and go up to 1 GB (2^30)
for i in {6..30}; do
    # Calculate the number of bytes as a power of two
    bytes=$((2**$i))
    
    echo "Running benchmark for $bytes bytes:"
    $PROGRAM $bytes
    echo ""
done

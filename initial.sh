#!/bin/bash

# Navigate to the sFuzz directory
cd sFuzz

# Create a build directory
mkdir -p build

# Move into the build directory
cd build

# Run cmake to configure the project
cmake ..

# Navigate to the fuzzer directory
cd fuzzer

# Compile the fuzzer
make

# Copy the compiled fuzzer to the target directory
cp fuzzer ../../../

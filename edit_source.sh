#!/bin/bash

# Navigate to the tools directory
cd tools

# Run the Python script
python3 rename.py

# Compile contracts_edit.cpp to create an executable named contracts_edit, linking the curl library
g++ contracts_edit.cpp -o contracts_edit -lcurl

# Execute the compiled contracts_edit program
./contracts_edit

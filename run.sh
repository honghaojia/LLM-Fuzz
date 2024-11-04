#!/bin/bash

# run LLM-Fuzz
./fuzzer -g -r 2 -d 300 && chmod +x fuzzMe && ./fuzzMe

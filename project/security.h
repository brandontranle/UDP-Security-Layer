#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void init_sec(int type, char* host);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void output_sec(uint8_t* buf, size_t length);

#pragma once

#include <Ws2tcpip.h>
#include <iostream>

#define LOG(x, ...) printf("[%s] %i: " x "\n", __FILE__, __LINE__, __VA_ARGS__)

#define MAX_BUFFER_SIZE 1000

#pragma once

#include <Ws2tcpip.h>
#include <iostream>

#define LOG(x, ...) printf("[%s] %i: " x "\n", __FILE__, __LINE__, __VA_ARGS__)

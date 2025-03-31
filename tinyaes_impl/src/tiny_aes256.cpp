#include "tiny_aes256.h"

#define AES256 1
#include <aes.hpp>

#include "tiny_aes_template.cpp"
TINY_AES_SOURCE_GENERATOR(AES_256)
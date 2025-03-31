#include "tiny_aes256.h"

#define AES256 1
#include <aes.hpp>

#include "tiny_aes_template.cpp"
TINY_AES_SOURCE_GENERATOR(AES_256)

template class AES_256<Mode::AES_ECB>;
template class AES_256<Mode::AES_CBC>;
template class AES_256<Mode::AES_CTR>;
#include "tiny_aes192.h"

#define AES192 1
#include <aes.hpp>

#include "tiny_aes_template.cpp"
TINY_AES_SOURCE_GENERATOR(AES_192)

template class AES_192<Mode::AES_ECB>;
template class AES_192<Mode::AES_CBC>;
template class AES_192<Mode::AES_CTR>;
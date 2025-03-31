#include "tiny_aes128.h"

#define AES128 1
#include <aes.hpp>

#include "tiny_aes_template.cpp"
TINY_AES_SOURCE_GENERATOR(AES_128)

template class AES_128<Mode::AES_ECB>;
template class AES_128<Mode::AES_CBC>;
template class AES_128<Mode::AES_CTR>;
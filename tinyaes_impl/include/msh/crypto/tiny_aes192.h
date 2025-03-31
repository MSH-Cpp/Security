#pragma once

#include "tiny_aes_template.h"
namespace msh::crypto {

TINY_AES_HEADER_GENERATOR(AES_192)

extern template class AES_192<Mode::AES_ECB>;
extern template class AES_192<Mode::AES_CBC>;
extern template class AES_192<Mode::AES_CTR>;

};  // namespace msh::crypto
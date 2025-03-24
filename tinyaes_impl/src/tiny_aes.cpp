#include "tiny_aes.h"

#include "tiny_aes128.h"
#include "tiny_aes192.h"
#include "tiny_aes256.h"

using namespace msh::crypto;
using namespace msh::utils;

AES::AES(const ByteArray& key, const AESInterface::Mode mode, const KeyLength keyLength)
    : AESInterface(key, mode) {
    switch (keyLength) {
        case KeyLength::AES_128: m_aes = std::make_unique<AES128_IMPL>(key, mode); break;
        case KeyLength::AES_192: m_aes = std::make_unique<AES192_IMPL>(key, mode); break;
        case KeyLength::AES_256: m_aes = std::make_unique<AES256_IMPL>(key, mode); break;
        default: throw std::invalid_argument("Invalid key length");
    }
}

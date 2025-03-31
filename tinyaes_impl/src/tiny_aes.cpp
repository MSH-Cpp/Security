#include "tiny_aes.h"

#include "tiny_aes128.h"
#include "tiny_aes192.h"
#include "tiny_aes256.h"

using namespace msh::crypto;
using namespace msh::utils;

template <Mode mode>
AES<mode>::AES(const ByteArray& key, const KeyLength keyLength) : AESInterface(key) {
    switch (keyLength) {
        case KeyLength::AES_128: m_aes = std::make_unique<AES_128<mode>>(key); break;
        case KeyLength::AES_192: m_aes = std::make_unique<AES_192<mode>>(key); break;
        case KeyLength::AES_256: m_aes = std::make_unique<AES_256<mode>>(key); break;
        default: throw std::invalid_argument("Invalid key length");
    }
}

template class AES<Mode::AES_ECB>;
template class AES<Mode::AES_CBC>;
template class AES<Mode::AES_CTR>;
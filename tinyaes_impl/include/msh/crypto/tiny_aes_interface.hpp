#pragma once

#include "interface.hpp"

namespace msh::crypto {

enum class Mode { AES_CBC, AES_ECB, AES_CTR };
enum class KeyLength { AES_128, AES_192, AES_256 };

class AESInterface : public CryptoInterface {
  public:
    explicit AESInterface(const utils::ByteArray& key) : CryptoInterface(key) {}
};

};  // namespace msh::crypto
#pragma once

#include <string>

#include "msh/utils/byte_array.hpp"

namespace msh::crypto {

class CryptoInterface {
  public:
    CryptoInterface(const utils::ByteArray& key) : m_key(key) {}
    virtual ~CryptoInterface() = default;

    // Core encryption/decryption methods
    virtual utils::ByteArray encrypt(const utils::ByteArray& data) = 0;
    virtual utils::ByteArray decrypt(const utils::ByteArray& data) = 0;

    // String convenience methods
    std::string encrypt(const std::string& input);
    std::string decrypt(const std::string& input);

  protected:
    utils::ByteArray m_key;
};

inline std::string CryptoInterface::encrypt(const std::string& input) {
    return encrypt(utils::ByteArray(input)).string();
}

inline std::string CryptoInterface::decrypt(const std::string& input) {
    return decrypt(utils::ByteArray(input)).string();
}

};  // namespace msh::crypto
#pragma once

#include <memory>

#include "tiny_aes_interface.hpp"

namespace msh::crypto {

class AES : public AESInterface {
  public:
    enum class KeyLength { AES_128, AES_192, AES_256 };

    explicit AES(const utils::ByteArray& key, const Mode mode,
                 const KeyLength keyLength = KeyLength::AES_128);

    // Interface implementation
    utils::ByteArray encrypt(const utils::ByteArray& data) override;
    utils::ByteArray decrypt(const utils::ByteArray& data) override;

    // Static convenience methods
    template <Mode mode, KeyLength keyLength>
    static std::string encrypt(const std::string& input, const std::string& key,
                               const std::string& iv = "");
    template <Mode mode, KeyLength keyLength>
    static std::string decrypt(const std::string& input, const std::string& key,
                               const std::string& iv = "");

  private:
    std::unique_ptr<AESInterface> m_aes;
};

inline utils::ByteArray AES::encrypt(const utils::ByteArray& data) {
    if (data.empty()) {
        return utils::ByteArray();
    }
    return m_aes->encrypt(data);
}

inline utils::ByteArray AES::decrypt(const utils::ByteArray& data) {
    if (data.empty()) {
        return utils::ByteArray();
    }
    return m_aes->decrypt(data);
}

template <AES::Mode mode, AES::KeyLength keyLength>
inline std::string AES::encrypt(const std::string& input, const std::string& key,
                                const std::string& iv) {
    return AES(utils::ByteArray(key), mode, keyLength).encrypt(utils::ByteArray(input)).string();
}

template <AES::Mode mode, AES::KeyLength keyLength>
inline std::string AES::decrypt(const std::string& input, const std::string& key,
                                const std::string& iv) {
    return AES(utils::ByteArray(key), mode, keyLength).decrypt(utils::ByteArray(input)).string();
}

}  // namespace msh::crypto
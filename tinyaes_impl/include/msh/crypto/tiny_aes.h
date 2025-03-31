#pragma once

#include <memory>

#include "tiny_aes_interface.hpp"

namespace msh::crypto {

template <Mode mode>
class AES : public AESInterface {
  public:
    explicit AES(const utils::ByteArray& key, const KeyLength keyLength = KeyLength::AES_128);

    // Interface implementation
    utils::ByteArray encrypt(const utils::ByteArray& data) override;
    utils::ByteArray decrypt(const utils::ByteArray& data) override;

    // Static convenience methods
    template <KeyLength keyLength>
    static std::string encrypt(const std::string& input, const std::string& key,
                               const std::string& iv = "");
    template <KeyLength keyLength>
    static std::string decrypt(const std::string& input, const std::string& key,
                               const std::string& iv = "");

  private:
    std::unique_ptr<AESInterface> m_aes;
};

template <Mode mode>
inline utils::ByteArray AES<mode>::encrypt(const utils::ByteArray& data) {
    if (data.empty()) {
        return utils::ByteArray();
    }
    return m_aes->encrypt(data);
}

template <Mode mode>
inline utils::ByteArray AES<mode>::decrypt(const utils::ByteArray& data) {
    if (data.empty()) {
        return utils::ByteArray();
    }
    return m_aes->decrypt(data);
}

template <Mode mode>
template <KeyLength keyLength>
inline std::string AES<mode>::encrypt(const std::string& input, const std::string& key,
                                      const std::string& iv) {
    return AES<mode>(utils::ByteArray(key), keyLength).encrypt(utils::ByteArray(input)).string();
}

template <Mode mode>
template <KeyLength keyLength>
inline std::string AES<mode>::decrypt(const std::string& input, const std::string& key,
                                      const std::string& iv) {
    return AES<mode>(utils::ByteArray(key), keyLength).decrypt(utils::ByteArray(input)).string();
}

extern template class AES<Mode::AES_ECB>;
extern template class AES<Mode::AES_CBC>;
extern template class AES<Mode::AES_CTR>;

}  // namespace msh::crypto
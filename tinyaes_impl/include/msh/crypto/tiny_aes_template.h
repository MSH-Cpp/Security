#include "tiny_aes_interface.hpp"

namespace msh::crypto {

class AES_TEMPLATE : public AESInterface {
  public:
    AES_TEMPLATE(const utils::ByteArray& key, const AESInterface::Mode mode);

    // Interface implementation
    utils::ByteArray encrypt(const utils::ByteArray& data) override {
        switch (m_mode) {
            case Mode::CBC: return encryptCBC(data);
            case Mode::ECB: return encryptECB(data);
            case Mode::CTR: return encryptCTR(data);
            default: throw std::invalid_argument("Invalid mode");
        }
    };
    utils::ByteArray decrypt(const utils::ByteArray& data) override {
        switch (m_mode) {
            case Mode::CBC: return decryptCBC(data);
            case Mode::ECB: return decryptECB(data);
            case Mode::CTR: return decryptCTR(data);
            default: throw std::invalid_argument("Invalid mode");
        }
    };

  private:
    // CBC Mode
    utils::ByteArray encryptCBC(const utils::ByteArray& data);
    utils::ByteArray decryptCBC(const utils::ByteArray& data);

    // ECB Mode
    utils::ByteArray encryptECB(const utils::ByteArray& data);
    utils::ByteArray decryptECB(const utils::ByteArray& data);

    // CTR Mode
    utils::ByteArray encryptCTR(const utils::ByteArray& data);
    utils::ByteArray decryptCTR(const utils::ByteArray& data);
};

}  // namespace msh::crypto

#pragma once

#include "interface.hpp"

namespace msh::crypto {

class AESInterface : public CryptoInterface {
  public:
    enum class Mode { CBC, ECB, CTR };

    explicit AESInterface(const utils::ByteArray& key, const Mode mode = Mode::CBC)
        : CryptoInterface(key), m_mode(mode) {}

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

  protected:
    Mode m_mode;

    // CBC Mode
    virtual utils::ByteArray encryptCBC(const utils::ByteArray& data) {
        return utils::ByteArray();
    };
    virtual utils::ByteArray decryptCBC(const utils::ByteArray& data) {
        return utils::ByteArray();
    };

    // ECB Mode
    virtual utils::ByteArray encryptECB(const utils::ByteArray& data) {
        return utils::ByteArray();
    };
    virtual utils::ByteArray decryptECB(const utils::ByteArray& data) {
        return utils::ByteArray();
    };

    // CTR Mode
    virtual utils::ByteArray encryptCTR(const utils::ByteArray& data) {
        return utils::ByteArray();
    };
    virtual utils::ByteArray decryptCTR(const utils::ByteArray& data) {
        return utils::ByteArray();
    };
};

};  // namespace msh::crypto
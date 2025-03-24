#pragma once

#include "tiny_aes_interface.hpp"

namespace msh::crypto {

class AES192_IMPL : public AESInterface {
  public:
    AES192_IMPL(const utils::ByteArray& key, const AESInterface::Mode mode);

  private:
    // CBC Mode
    utils::ByteArray encryptCBC(const utils::ByteArray& data) override;
    utils::ByteArray decryptCBC(const utils::ByteArray& data) override;

    // ECB Mode
    utils::ByteArray encryptECB(const utils::ByteArray& data) override;
    utils::ByteArray decryptECB(const utils::ByteArray& data) override;

    // CTR Mode
    utils::ByteArray encryptCTR(const utils::ByteArray& data) override;
};

}  // namespace msh::crypto

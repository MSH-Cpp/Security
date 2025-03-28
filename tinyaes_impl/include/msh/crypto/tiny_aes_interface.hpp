#pragma once

#include "interface.hpp"

namespace msh::crypto {

class AESInterface : public CryptoInterface {
  public:
    enum class Mode { CBC, ECB, CTR };

    explicit AESInterface(const utils::ByteArray& key, const Mode mode = Mode::CBC)
        : CryptoInterface(key), m_mode(mode) {}

  protected:
    Mode m_mode;
};

};  // namespace msh::crypto
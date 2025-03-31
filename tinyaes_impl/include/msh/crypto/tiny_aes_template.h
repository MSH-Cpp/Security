#include "tiny_aes_interface.hpp"

#define TINY_AES_HEADER_GENERATOR(AES_TEMPLATE)                           \
                                                                          \
    template <Mode mode>                                                  \
    class AES_TEMPLATE : public AESInterface {                            \
      public:                                                             \
        explicit AES_TEMPLATE(const utils::ByteArray& key);               \
                                                                          \
        /* Interface implementation */                                    \
        utils::ByteArray encrypt(const utils::ByteArray& data) override { \
            if constexpr (mode == Mode::AES_ECB) {                        \
                return encryptECB(data);                                  \
            } else if constexpr (mode == Mode::AES_CBC) {                 \
                return encryptCBC(data);                                  \
            } else if constexpr (mode == Mode::AES_CTR) {                 \
                return encryptCTR(data);                                  \
            } else {                                                      \
                static_assert(false, "Invalid mode");                     \
            }                                                             \
        }                                                                 \
        utils::ByteArray decrypt(const utils::ByteArray& data) override { \
            if constexpr (mode == Mode::AES_ECB) {                        \
                return decryptECB(data);                                  \
            } else if constexpr (mode == Mode::AES_CBC) {                 \
                return decryptCBC(data);                                  \
            } else if constexpr (mode == Mode::AES_CTR) {                 \
                return decryptCTR(data);                                  \
            } else {                                                      \
                static_assert(false, "Invalid mode");                     \
            }                                                             \
        };                                                                \
                                                                          \
      private: /* CBC Mode */                                             \
        utils::ByteArray encryptCBC(const utils::ByteArray& data);        \
        utils::ByteArray decryptCBC(const utils::ByteArray& data);        \
                                                                          \
        /* ECB Mode */                                                    \
        utils::ByteArray encryptECB(const utils::ByteArray& data);        \
        utils::ByteArray decryptECB(const utils::ByteArray& data);        \
                                                                          \
        /* CTR Mode */                                                    \
        utils::ByteArray encryptCTR(const utils::ByteArray& data);        \
        utils::ByteArray decryptCTR(const utils::ByteArray& data);        \
    };
#include <cstring>
#include <stdexcept>

#define TO_STRING(x) #x

#define TINY_AES_SOURCE_GENERATOR(AES_TEMPLATE)                                                    \
                                                                                                   \
    using namespace msh::crypto;                                                                   \
    using namespace msh::utils;                                                                    \
                                                                                                   \
    template <Mode mode>                                                                           \
    AES_TEMPLATE<mode>::AES_TEMPLATE(const ByteArray& key) : AESInterface(key) {                   \
        if (m_key.size() != AES_KEYLEN) {                                                          \
            throw std::invalid_argument("Key size must be " TO_STRING(AES_KEYLEN) " bytes");       \
        }                                                                                          \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::encryptCBC(const ByteArray& data) {                              \
        ByteArray iv(AES_BLOCKLEN);                                                                \
        std::generate(iv.begin(), iv.end(), std::rand); /* Generate random IV */                   \
                                                                                                   \
        ByteArray plaintext = data;                                                                \
        size_t paddedLength =                                                                      \
            plaintext.size() + (AES_BLOCKLEN - (plaintext.size() % AES_BLOCKLEN));                 \
        plaintext.resize(paddedLength,                                                             \
                         AES_BLOCKLEN - (plaintext.size() % AES_BLOCKLEN)); /* PKCS7 Padding */    \
                                                                                                   \
        struct AES_ctx ctx;                                                                        \
        AES_init_ctx_iv(&ctx, m_key.data(), iv.data());                                            \
        AES_CBC_encrypt_buffer(&ctx, plaintext.data(), plaintext.size());                          \
                                                                                                   \
        ByteArray ciphertext = iv; /* Prepend IV */                                                \
        ciphertext.insert(ciphertext.end(), plaintext.begin(), plaintext.end());                   \
        return ciphertext;                                                                         \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::decryptCBC(const ByteArray& data) {                              \
        if (data.size() < AES_BLOCKLEN)                                                            \
            throw std::runtime_error("Ciphertext too short!");                                     \
                                                                                                   \
        ByteArray iv(data.begin(), data.begin() + AES_BLOCKLEN);                                   \
        ByteArray ciphertext(data.begin() + AES_BLOCKLEN, data.end());                             \
                                                                                                   \
        struct AES_ctx ctx;                                                                        \
        AES_init_ctx_iv(&ctx, m_key.data(), iv.data());                                            \
        AES_CBC_decrypt_buffer(&ctx, ciphertext.data(), ciphertext.size());                        \
                                                                                                   \
        /* Remove PKCS7 padding */                                                                 \
        size_t padLength = ciphertext.back();                                                      \
        if (padLength > AES_BLOCKLEN)                                                              \
            throw std::runtime_error("Invalid padding!");                                          \
        ciphertext.resize(ciphertext.size() - padLength);                                          \
                                                                                                   \
        return ciphertext;                                                                         \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::encryptECB(const ByteArray& data) {                              \
        ByteArray plaintext = data;                                                                \
        size_t paddedLength =                                                                      \
            plaintext.size() + (AES_BLOCKLEN - (plaintext.size() % AES_BLOCKLEN));                 \
        plaintext.resize(paddedLength, AES_BLOCKLEN - (plaintext.size() % AES_BLOCKLEN));          \
                                                                                                   \
        struct AES_ctx ctx;                                                                        \
        AES_init_ctx(&ctx, m_key.data());                                                          \
                                                                                                   \
        for (size_t i = 0; i < plaintext.size(); i += AES_BLOCKLEN) {                              \
            AES_ECB_encrypt(&ctx, plaintext.data() + i);                                           \
        }                                                                                          \
                                                                                                   \
        return plaintext;                                                                          \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::decryptECB(const ByteArray& data) {                              \
        ByteArray ciphertext = data;                                                               \
                                                                                                   \
        struct AES_ctx ctx;                                                                        \
        AES_init_ctx(&ctx, m_key.data());                                                          \
        AES_ECB_decrypt(&ctx, ciphertext.data());                                                  \
                                                                                                   \
        /* Remove padding (assuming PKCS7 padding) */                                              \
        size_t padLength = ciphertext.back();                                                      \
        ciphertext.resize(ciphertext.size() - padLength);                                          \
                                                                                                   \
        return ciphertext;                                                                         \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::encryptCTR(const ByteArray& data) {                              \
        ByteArray iv(AES_BLOCKLEN);                                                                \
        std::generate(iv.begin(), iv.end(), std::rand); /* Generate random IV (Nonce + Counter) */ \
                                                                                                   \
        ByteArray ciphertext = data; /* Create buffer for ciphertext */                            \
                                                                                                   \
        struct AES_ctx ctx;                                                                        \
        AES_init_ctx_iv(&ctx, m_key.data(), iv.data());                                            \
                                                                                                   \
        /* Encrypt/decrypt in-place */                                                             \
        AES_CTR_xcrypt_buffer(&ctx, ciphertext.data(), ciphertext.size());                         \
                                                                                                   \
        /* Prepend IV to ciphertext */                                                             \
        ByteArray output = iv;                                                                     \
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());                         \
        return output;                                                                             \
    }                                                                                              \
                                                                                                   \
    template <Mode mode>                                                                           \
    ByteArray AES_TEMPLATE<mode>::decryptCTR(const utils::ByteArray& data) {                       \
        return encryptCTR(data);                                                                   \
    };
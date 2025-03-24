#include <catch2/catch_test_macros.hpp>

#include "msh/crypto/tiny_aes.h"

TEST_CASE("AES Encryption/Decryption", "[aes]") {
    const std::string key = "0123456789abcdef";  // 16-byte key
    const std::string iv = "0123456789abcdef";   // 16-byte IV
    const std::string plaintext = "Hello, World!";

    SECTION("Using AES class directly") {
        msh::crypto::AES aes(msh::utils::ByteArray(key), msh::crypto::AES::Mode::ECB);

        std::string encrypted = aes.encrypt(msh::utils::ByteArray(plaintext)).string();
        std::string decrypted = aes.decrypt(msh::utils::ByteArray(encrypted)).string();

        REQUIRE(decrypted == plaintext);
        REQUIRE(encrypted != plaintext);  // Ensure encryption actually changed the text
    }

    SECTION("Using static convenience methods") {
        std::string encrypted =
            msh::crypto::AES::encrypt<msh::crypto::AES::Mode::ECB,
                                      msh::crypto::AES::KeyLength::AES_128>(plaintext, key, iv);
        std::string decrypted =
            msh::crypto::AES::decrypt<msh::crypto::AES::Mode::ECB,
                                      msh::crypto::AES::KeyLength::AES_128>(encrypted, key, iv);

        REQUIRE(decrypted == plaintext);
        REQUIRE(encrypted != plaintext);
    }

    SECTION("Empty string") {
        msh::crypto::AES aes(msh::utils::ByteArray(key), msh::crypto::AES::Mode::ECB);
        std::string empty = "";

        std::string encrypted = aes.encrypt(msh::utils::ByteArray(empty)).string();
        std::string decrypted = aes.decrypt(msh::utils::ByteArray(encrypted)).string();

        REQUIRE(decrypted == empty);
    }

    SECTION("Invalid key length") {
        std::string invalid_key = "short";  // Too short
        REQUIRE_THROWS_AS(
            msh::crypto::AES(msh::utils::ByteArray(invalid_key), msh::crypto::AES::Mode::ECB),
            std::invalid_argument);
    }

    SECTION("Different key lengths") {
        // Test AES-128
        std::string key_128 = "0123456789abcdef";  // 16 bytes
        auto aes_128 = msh::crypto::AES(msh::utils::ByteArray(key_128),
                                        msh::crypto::AES::Mode::ECB,
                                        msh::crypto::AES::KeyLength::AES_128);
        auto encrypted_128 = aes_128.encrypt(msh::utils::ByteArray(plaintext));
        auto decrypted_128 = aes_128.decrypt(encrypted_128);
        REQUIRE(decrypted_128.string() == plaintext);

        // Test AES-192
        std::string key_192 = "0123456789abcdef01234567";  // 24 bytes
        auto aes_192 = msh::crypto::AES(msh::utils::ByteArray(key_192),
                                        msh::crypto::AES::Mode::ECB,
                                        msh::crypto::AES::KeyLength::AES_192);
        auto encrypted_192 = aes_192.encrypt(msh::utils::ByteArray(plaintext));
        auto decrypted_192 = aes_192.decrypt(encrypted_192);
        REQUIRE(decrypted_192.string() == plaintext);

        // Test AES-256
        std::string key_256 = "0123456789abcdef0123456789abcdef";  // 32 bytes
        auto aes_256 = msh::crypto::AES(msh::utils::ByteArray(key_256),
                                        msh::crypto::AES::Mode::ECB,
                                        msh::crypto::AES::KeyLength::AES_256);
        auto encrypted_256 = aes_256.encrypt(msh::utils::ByteArray(plaintext));
        auto decrypted_256 = aes_256.decrypt(encrypted_256);
        REQUIRE(decrypted_256.string() == plaintext);
    }
}
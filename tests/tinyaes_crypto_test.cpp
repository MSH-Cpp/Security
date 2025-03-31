#include <catch2/catch_test_macros.hpp>

#include "msh/crypto/tiny_aes.h"

using namespace msh::crypto;
using namespace msh::utils;

TEST_CASE("AES<Mode::AES_ECB> Encryption/Decryption", "[aes]") {
    const std::string key_128 = "0123456789abcdef";                  // 16-byte key
    const std::string key_192 = "0123456789abcdef01234567";          // 24-byte key
    const std::string key_256 = "0123456789abcdef0123456789abcdef";  // 32-byte key
    const std::string plaintext = "Hello, World!";

    SECTION("Using AES<Mode::AES_ECB> class directly") {
        AES<Mode::AES_ECB> aes(ByteArray(key_128), KeyLength::AES_128);

        std::string encrypted = aes.encrypt(ByteArray(plaintext)).string();
        std::string decrypted = aes.decrypt(ByteArray(encrypted)).string();

        REQUIRE(decrypted == plaintext);
        REQUIRE(encrypted != plaintext);  // Ensure encryption actually changed the text
    }

    SECTION("Using static convenience methods") {
        std::string encrypted = AES<Mode::AES_ECB>::encrypt<KeyLength::AES_128>(plaintext, key_128);
        std::string decrypted = AES<Mode::AES_ECB>::decrypt<KeyLength::AES_128>(encrypted, key_128);

        REQUIRE(decrypted == plaintext);
        REQUIRE(encrypted != plaintext);
    }

    SECTION("Empty string") {
        std::string empty = "";
        AES<Mode::AES_ECB> aes(ByteArray(key_128), KeyLength::AES_128);

        std::string encrypted = aes.encrypt(ByteArray(empty)).string();
        std::string decrypted = aes.decrypt(ByteArray(encrypted)).string();

        REQUIRE(decrypted == empty);
    }

    SECTION("Invalid key length") {
        std::string invalid_key = "short";  // Too short
        REQUIRE_THROWS_AS(AES<Mode::AES_ECB>(ByteArray(invalid_key), KeyLength::AES_128),
                          std::invalid_argument);
    }

    SECTION("Different key lengths") {
        // Test AES-128
        auto aes_128 = AES<Mode::AES_ECB>(ByteArray(key_128), KeyLength::AES_128);
        auto encrypted_128 = aes_128.encrypt(ByteArray(plaintext));
        auto decrypted_128 = aes_128.decrypt(encrypted_128);
        REQUIRE(decrypted_128.string() == plaintext);

        // Test AES-192
        auto aes_192 = AES<Mode::AES_ECB>(ByteArray(key_192), KeyLength::AES_192);
        auto encrypted_192 = aes_192.encrypt(ByteArray(plaintext));
        auto decrypted_192 = aes_192.decrypt(encrypted_192);
        REQUIRE(decrypted_192.string() == plaintext);

        // Test AES-256
        auto aes_256 = AES<Mode::AES_ECB>(ByteArray(key_256), KeyLength::AES_256);
        auto encrypted_256 = aes_256.encrypt(ByteArray(plaintext));
        auto decrypted_256 = aes_256.decrypt(encrypted_256);
        REQUIRE(decrypted_256.string() == plaintext);
    }
}
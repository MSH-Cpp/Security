# MSH Crypto Library

A C++ library for AES encryption and decryption using the tiny-aes-c library.

## Features

- AES encryption and decryption
- Support for 128-bit, 192-bit, and 256-bit keys
- ECB mode encryption
- PKCS7 padding
- String-based convenience functions
- Uses MSH ByteArray for binary data handling

## Requirements

- C++17 or later
- CMake 3.15 or later
- tiny-aes-c library
- Catch2 (for tests)

## Building

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

```cpp
#include <msh/crypto/aes_crypto.hpp>

// Using convenience functions
std::string key = "0123456789abcdef";  // 16-byte key
std::string iv = "0123456789abcdef";   // 16-byte IV
std::string plaintext = "Hello, World!";

std::string encrypted = msh::crypto::encrypt(plaintext, key, iv);
std::string decrypted = msh::crypto::decrypt(encrypted, key, iv);

// Using the AES class directly
msh::crypto::AES aes(msh::utils::ByteArray(key));
std::string encrypted = aes.encryptString(plaintext);
std::string decrypted = aes.decryptString(encrypted);
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace pm {

std::vector<uint8_t> random_bytes(size_t length) {
    std::vector<uint8_t> buf(length);
    if (RAND_bytes(buf.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buf;
}

std::vector<uint8_t> derive_key(const std::string& password,
                                const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(
            password.c_str(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()),
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            KEY_LEN, key.data()) != 1) {
        throw std::runtime_error("PBKDF2 failed");
    }
    return key;
}

std::vector<uint8_t> make_password_verifier(const std::string& password,
                                            const std::vector<uint8_t>& salt) {
    auto key = derive_key(password, salt);
    // HMAC of a fixed string under the key → verifier
    const char* msg = "PasswordManagerVerifier";
    unsigned int len = 0;
    std::vector<uint8_t> verifier(EVP_MAX_MD_SIZE);
    if (HMAC(EVP_sha256(),
             key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(msg), std::strlen(msg),
             verifier.data(), &len) == nullptr) {
        secure_wipe(key);
        throw std::runtime_error("HMAC failed");
    }
    verifier.resize(len);
    secure_wipe(key);
    return verifier;
}

bool verify_password(const std::string& password,
                     const std::vector<uint8_t>& salt,
                     const std::vector<uint8_t>& verifier) {
    try {
        auto computed = make_password_verifier(password, salt);
        // Constant-time comparison
        if (computed.size() != verifier.size()) {
            secure_wipe(computed);
            return false;
        }
        int diff = 0;
        for (size_t i = 0; i < computed.size(); ++i) {
            diff |= computed[i] ^ verifier[i];
        }
        secure_wipe(computed);
        return diff == 0;
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("Invalid key length");
    }

    auto iv = random_bytes(IV_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                               key.data(), iv.data()) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // Prepend IV
        std::vector<uint8_t> result;
        result.reserve(IV_LEN + ciphertext.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        EVP_CIPHER_CTX_free(ctx);
        return result;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                             const std::vector<uint8_t>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("Invalid key length");
    }
    if (data.size() < static_cast<size_t>(IV_LEN + 1)) {
        throw std::runtime_error("Ciphertext too short");
    }

    std::vector<uint8_t> iv(data.begin(), data.begin() + IV_LEN);
    std::vector<uint8_t> ciphertext(data.begin() + IV_LEN, data.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                               key.data(), iv.data()) != 1) {
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1) {
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }
        plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            throw std::runtime_error("Decryption failed (wrong key or corrupted data)");
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

void secure_wipe(std::string& s) {
    if (!s.empty()) {
        OPENSSL_cleanse(&s[0], s.size());
        s.clear();
    }
}

void secure_wipe(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size());
        v.clear();
    }
}

} // namespace pm

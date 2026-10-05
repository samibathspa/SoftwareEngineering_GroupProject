#pragma once
/**
 * Cryptography helpers for the Password Manager.
 * Uses OpenSSL: PBKDF2-HMAC-SHA256 for key derivation,
 * AES-256-CBC for encryption (IV prepended to ciphertext).
 *
 * Layer: Domain / Cryptography (as described in the project report)
 */

#include <string>
#include <vector>
#include <cstdint>

namespace pm {

// Derived key length for AES-256
constexpr int KEY_LEN = 32;
// Salt length
constexpr int SALT_LEN = 16;
// IV length for AES
constexpr int IV_LEN = 16;
// PBKDF2 iteration count (reasonable for a student project)
constexpr int PBKDF2_ITERATIONS = 100000;

/**
 * Generate cryptographically secure random bytes.
 */
std::vector<uint8_t> random_bytes(size_t length);

/**
 * Derive a 32-byte key from password + salt using PBKDF2-HMAC-SHA256.
 */
std::vector<uint8_t> derive_key(const std::string& password,
                                const std::vector<uint8_t>& salt);

/**
 * Create a verification hash (for checking the master password without
 * storing it). We store: salt + HMAC of a constant under the derived key.
 * Returns a binary blob that can be written into the vault header.
 */
std::vector<uint8_t> make_password_verifier(const std::string& password,
                                            const std::vector<uint8_t>& salt);

/**
 * Check whether the given password matches the stored verifier + salt.
 */
bool verify_password(const std::string& password,
                     const std::vector<uint8_t>& salt,
                     const std::vector<uint8_t>& verifier);

/**
 * Encrypt plaintext with AES-256-CBC.
 * Output format: IV (16 bytes) || ciphertext
 */
std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key);

/**
 * Decrypt data produced by encrypt().
 * Throws std::runtime_error on failure.
 */
std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                             const std::vector<uint8_t>& key);

/**
 * Best-effort secure wipe of a string (overwrites then clears).
 */
void secure_wipe(std::string& s);

/**
 * Best-effort secure wipe of a byte vector.
 */
void secure_wipe(std::vector<uint8_t>& v);

} // namespace pm

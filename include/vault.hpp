#pragma once
/**
 * Vault – encrypted credential store.
 * Layer: Domain + Persistence (as described in the project report)
 *
 * File format (binary):
 *   Magic (4 bytes) "PMV1"
 *   Salt  (16 bytes)
 *   Verifier length (4 bytes, little-endian) + Verifier bytes
 *   Encrypted payload (AES-256-CBC, IV prepended)
 *
 * Payload (after decryption) is a simple text serialisation of records.
 */

#include "crypto.hpp"
#include <string>
#include <vector>
#include <optional>
#include <fstream>

namespace pm {

struct Credential {
    int id = 0;
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
};

class Vault {
public:
    explicit Vault(std::string path);

    // Returns true if the vault file already exists on disk
    bool exists() const;

    // First-run: create a new vault with the given master password
    void create(const std::string& master_password);

    // Unlock an existing vault. Returns false on wrong password.
    bool unlock(const std::string& master_password);

    // Lock / clear in-memory data
    void lock();

    bool is_unlocked() const { return unlocked_; }

    // CRUD
    std::vector<Credential> list() const;
    std::optional<Credential> get(int id) const;
    int add(const std::string& service,
            const std::string& username,
            const std::string& password,
            const std::string& notes = "");
    bool update(int id,
                const std::string& service,
                const std::string& username,
                const std::string& password,
                const std::string& notes);
    bool remove(int id);

    // Simple case-insensitive search on service name
    std::vector<Credential> search(const std::string& query) const;

    // Persist current in-memory state (must be unlocked)
    void save();

private:
    std::string path_;
    bool unlocked_ = false;
    std::vector<uint8_t> salt_;
    std::vector<uint8_t> verifier_;
    std::vector<uint8_t> key_;          // derived key (wiped on lock)
    std::vector<Credential> entries_;
    int next_id_ = 1;

    std::vector<uint8_t> serialise() const;
    void deserialise(const std::vector<uint8_t>& data);
    void write_file(const std::vector<uint8_t>& encrypted_payload) const;
    std::vector<uint8_t> read_file() const;
};

} // namespace pm

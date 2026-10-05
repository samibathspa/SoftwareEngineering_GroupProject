#include "vault.hpp"

#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>

namespace pm {

namespace {
constexpr char MAGIC[4] = {'P', 'M', 'V', '1'};

void write_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

uint32_t read_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
} // namespace

Vault::Vault(std::string path) : path_(std::move(path)) {}

bool Vault::exists() const {
    std::ifstream f(path_, std::ios::binary);
    return f.good();
}

void Vault::create(const std::string& master_password) {
    if (master_password.empty()) {
        throw std::runtime_error("Master password cannot be empty");
    }
    salt_ = random_bytes(SALT_LEN);
    verifier_ = make_password_verifier(master_password, salt_);
    key_ = derive_key(master_password, salt_);
    entries_.clear();
    next_id_ = 1;
    unlocked_ = true;
    save();
}

bool Vault::unlock(const std::string& master_password) {
    if (!exists()) {
        throw std::runtime_error("Vault file does not exist");
    }

    auto file_data = read_file();
    if (file_data.size() < 4 + SALT_LEN + 4) {
        throw std::runtime_error("Vault file is corrupted or too short");
    }

    // Magic
    if (std::memcmp(file_data.data(), MAGIC, 4) != 0) {
        throw std::runtime_error("Not a valid password vault file");
    }

    size_t offset = 4;
    salt_.assign(file_data.begin() + offset,
                 file_data.begin() + offset + SALT_LEN);
    offset += SALT_LEN;

    uint32_t ver_len = read_u32(file_data.data() + offset);
    offset += 4;
    if (offset + ver_len > file_data.size()) {
        throw std::runtime_error("Vault file is corrupted");
    }
    verifier_.assign(file_data.begin() + offset,
                     file_data.begin() + offset + ver_len);
    offset += ver_len;

    if (!verify_password(master_password, salt_, verifier_)) {
        return false; // wrong password
    }

    key_ = derive_key(master_password, salt_);

    std::vector<uint8_t> encrypted(file_data.begin() + offset, file_data.end());
    try {
        auto plain = decrypt(encrypted, key_);
        deserialise(plain);
        secure_wipe(plain);
    } catch (const std::exception&) {
        secure_wipe(key_);
        return false;
    }

    unlocked_ = true;
    return true;
}

void Vault::lock() {
    secure_wipe(key_);
    for (auto& e : entries_) {
        secure_wipe(e.password);
        secure_wipe(e.username);
        secure_wipe(e.notes);
        secure_wipe(e.service);
    }
    entries_.clear();
    unlocked_ = false;
}

std::vector<Credential> Vault::list() const {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    return entries_;
}

std::optional<Credential> Vault::get(int id) const {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    for (const auto& e : entries_) {
        if (e.id == id) return e;
    }
    return std::nullopt;
}

int Vault::add(const std::string& service,
               const std::string& username,
               const std::string& password,
               const std::string& notes) {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    if (service.empty()) throw std::runtime_error("Service name cannot be empty");

    Credential c;
    c.id = next_id_++;
    c.service = service;
    c.username = username;
    c.password = password;
    c.notes = notes;
    entries_.push_back(c);
    save();
    return c.id;
}

bool Vault::update(int id,
                   const std::string& service,
                   const std::string& username,
                   const std::string& password,
                   const std::string& notes) {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    for (auto& e : entries_) {
        if (e.id == id) {
            e.service = service;
            e.username = username;
            e.password = password;
            e.notes = notes;
            save();
            return true;
        }
    }
    return false;
}

bool Vault::remove(int id) {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const Credential& c) { return c.id == id; });
    if (it == entries_.end()) return false;
    secure_wipe(it->password);
    entries_.erase(it);
    save();
    return true;
}

std::vector<Credential> Vault::search(const std::string& query) const {
    if (!unlocked_) throw std::runtime_error("Vault is locked");
    std::string q = to_lower(query);
    std::vector<Credential> result;
    for (const auto& e : entries_) {
        if (to_lower(e.service).find(q) != std::string::npos) {
            result.push_back(e);
        }
    }
    return result;
}

void Vault::save() {
    if (!unlocked_) throw std::runtime_error("Cannot save while locked");
    auto plain = serialise();
    auto encrypted = encrypt(plain, key_);
    secure_wipe(plain);
    write_file(encrypted);
}

// ---------- private helpers ----------

std::vector<uint8_t> Vault::serialise() const {
    // Simple text format, one record per block:
    // ID|service|username|password|notes\n
    // Fields are length-prefixed to allow | inside values.
    // Format: <id>\n<len>:<service>\n<len>:<username>\n<len>:<password>\n<len>:<notes>\n
    std::ostringstream oss;
    oss << "NEXTID:" << next_id_ << "\n";
    for (const auto& e : entries_) {
        oss << "ENTRY\n";
        oss << e.id << "\n";
        oss << e.service.size() << ":" << e.service << "\n";
        oss << e.username.size() << ":" << e.username << "\n";
        oss << e.password.size() << ":" << e.password << "\n";
        oss << e.notes.size() << ":" << e.notes << "\n";
    }
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

void Vault::deserialise(const std::vector<uint8_t>& data) {
    entries_.clear();
    std::string s(data.begin(), data.end());
    std::istringstream iss(s);
    std::string line;

    if (!std::getline(iss, line) || line.rfind("NEXTID:", 0) != 0) {
        throw std::runtime_error("Invalid vault payload");
    }
    next_id_ = std::stoi(line.substr(7));

    auto read_field = [&](std::string& out) {
        if (!std::getline(iss, line)) throw std::runtime_error("Truncated payload");
        auto colon = line.find(':');
        if (colon == std::string::npos) throw std::runtime_error("Bad field format");
        size_t len = std::stoul(line.substr(0, colon));
        out = line.substr(colon + 1);
        if (out.size() != len) {
            // field may contain newlines – not supported in this simple format
            // for a student project we keep values single-line
        }
    };

    while (std::getline(iss, line)) {
        if (line != "ENTRY") continue;
        Credential c;
        if (!std::getline(iss, line)) break;
        c.id = std::stoi(line);
        read_field(c.service);
        read_field(c.username);
        read_field(c.password);
        read_field(c.notes);
        entries_.push_back(std::move(c));
    }
}

void Vault::write_file(const std::vector<uint8_t>& encrypted_payload) const {
    std::vector<uint8_t> out;
    out.insert(out.end(), MAGIC, MAGIC + 4);
    out.insert(out.end(), salt_.begin(), salt_.end());
    write_u32(out, static_cast<uint32_t>(verifier_.size()));
    out.insert(out.end(), verifier_.begin(), verifier_.end());
    out.insert(out.end(), encrypted_payload.begin(), encrypted_payload.end());

    std::ofstream f(path_, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot open vault file for writing");
    f.write(reinterpret_cast<const char*>(out.data()),
            static_cast<std::streamsize>(out.size()));
    if (!f) throw std::runtime_error("Failed to write vault file");
}

std::vector<uint8_t> Vault::read_file() const {
    std::ifstream f(path_, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open vault file for reading");
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    if (!f) throw std::runtime_error("Failed to read vault file");
    return data;
}

} // namespace pm

# Desktop Password Manager (C++)

## Features

- Master-password authentication (login / logout)
- Encrypted local vault file (`vault.dat`)
  - PBKDF2-HMAC-SHA256 key derivation (100 000 iterations)
  - AES-256-CBC encryption (random IV prepended)
- Credential CRUD: Add, List, View, Edit, Delete
- Simple search by service name
- Console menu UI
- Secure wipe of sensitive buffers where practical

## Requirements

- C++17 compiler (g++ 7+, clang, MSVC, …)
- CMake ≥ 3.14
- OpenSSL development libraries (`libssl-dev` / `openssl-devel`)

### Ubuntu / Debian
```bash
sudo apt install build-essential cmake libssl-dev
```

### Fedora
```bash
sudo dnf install gcc-c++ cmake openssl-devel
```

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

The binary `password_manager` will appear in the `build` directory.

## Run

```bash
./password_manager
```

On first launch the program creates `vault.dat` in the current working directory and asks you to set a master password.  
Subsequent launches prompt for that password.

## Project layout

```
password_manager/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── crypto.hpp      # Key derivation, AES, secure wipe
│   └── vault.hpp       # Credential model + encrypted store
└── src/
    ├── main.cpp        # Console UI / application flow
    ├── crypto.cpp
    └── vault.cpp
```

## Security notes (student-project scope)

- The master password is never stored in plaintext; only a salt + verifier are kept.
- The vault payload is encrypted; an attacker who steals `vault.dat` still faces a brute-force search against the master password.
- In-memory secrets are wiped on logout / program exit where the OpenSSL API permits.
- This is **not** a production password manager: it does not protect against memory scraping, side-channel attacks, or sophisticated malware. It is intended as a clear illustration of the architecture and process described in the project report.



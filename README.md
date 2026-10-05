# Desktop Password Manager (C++)

A desktop password manager for Windows with a graphical login window and an encrypted local vault. It was built for the Software Engineering group project.

## Features

- Graphical window (Windows API) with **Log In**, **Log Out** and **Recover Password** buttons
- Master-password protection. The first Log In creates a new vault, and later Log Ins unlock it
- Master password rules: at least 12 characters, with at least one uppercase letter, one lowercase letter, one number and one special character. A message explains which rule failed
- **Show password** checkbox on the password field
- **Light Mode / Dark Mode** toggle button
- **Recover Password** explains that the master password cannot be recovered (it is never stored) and offers to reset the vault after two confirmations. Resetting permanently deletes all saved credentials
- Encrypted local vault file (`vault.dat`)
  - PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
  - AES-256-CBC encryption (random IV prepended)
- Stored credentials are listed in the window after logging in
- Secure wipe of sensitive buffers where practical

## Requirements

- Windows 10 or 11
- [MSYS2](https://www.msys2.org) with the UCRT64 environment
- CMake 3.14 or later, Ninja, a C++17 compiler (g++) and OpenSSL

## Build (Windows, MSYS2 UCRT64)

1. Install MSYS2, then open the **MSYS2 UCRT64** terminal (not MSYS or MINGW64).
2. Install the tools:

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-openssl
```

3. Clone or download this repository, then go into its folder:

```bash
cd /c/path/to/this/repository
mkdir build
cd build
cmake ..
ninja
```

`password_manager.exe` will appear in the `build` folder.

## Run

From the same MSYS2 UCRT64 terminal, inside the `build` folder:

```bash
./password_manager.exe
```

On first launch there is no vault yet. Enter a master password that meets the rules and click **Log In** to create `vault.dat` in the current folder. On later launches, enter the same password to unlock it.

Note: double-clicking `password_manager.exe` in File Explorer can fail with a missing DLL error (for example `libcrypto-3-x64.dll`), because Windows cannot find the MSYS2 libraries. Running it from the UCRT64 terminal avoids this.

## Project layout

```
.
├── CMakeLists.txt
├── README.md
├── include/
│   ├── crypto.hpp      # Key derivation, AES, secure wipe
│   └── vault.hpp       # Credential model + encrypted store
└── src/
    ├── main.cpp        # Windows GUI and application flow
    ├── crypto.cpp
    └── vault.cpp
```

## Known limitations

- The window currently supports logging in, logging out, resetting the vault and listing stored credentials. Adding, editing and deleting credentials is implemented in the vault code (`vault.hpp` / `vault.cpp`) but does not yet have buttons in the window.
- Windows only.

## Security notes (student-project scope)

- The master password is never stored, in plaintext or in reversible form. Only a salt and a verifier are kept, so a forgotten master password cannot be recovered. Resetting the vault is the only option.
- The vault payload is encrypted. An attacker who steals `vault.dat` still faces a brute-force search against the master password.
- In-memory secrets are wiped on logout and program exit where the OpenSSL API permits.
- This is **not** a production password manager. It does not protect against memory scraping, side-channel attacks or sophisticated malware. It illustrates the architecture and process described in the project report.

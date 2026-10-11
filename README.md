# Desktop Password Manager (C++)

A desktop password manager for Windows with a graphical login window and an encrypted local vault. It was built for the Software Engineering group project.

## Features

- Graphical window (Windows API) with **Create Account**, **Log In**, **Log Out** and **Recover Password** actions
- **Create Account** setup asks for a strong master password and confirmation; the app currently supports one account per local vault
- Master-password protection. Log Ins unlock the existing vault
- Master password rules: at least 12 characters, with at least one uppercase letter, one lowercase letter, one number and one special character. A message explains which rule failed
- **Show password** checkbox on the password field
- **Light Mode / Dark Mode** toggle button
- Compact login window that expands to a smaller credential workspace after login
- **Recover Password** explains that the master password cannot be recovered (it is never stored) and offers to reset the vault after two confirmations. Resetting permanently deletes all saved credentials
- Encrypted local vault file (`vault.dat`)
  - PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
  - AES-256-CBC encryption (random IV prepended)
- Logged-in credential workspace with actions to list, add, edit, delete, search by service, and view saved credentials
- Strong random password generator in the add/edit credential form, with an option to reveal the generated password
- **Exit** button in the logged-in workspace
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

On first launch there is no vault yet. Choose **Create Account**, enter a master password that meets the rules, and confirm it to create `vault.dat` in the current folder. On later launches, enter the same password to unlock the vault.

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

- Windows only.

## Security notes (student-project scope)

- The master password is never stored, in plaintext or in reversible form. Only a salt and a verifier are kept, so a forgotten master password cannot be recovered. Resetting the vault is the only option.
- The vault payload is encrypted. An attacker who steals `vault.dat` still faces a brute-force search against the master password.
- In-memory secrets are wiped on logout and program exit where the OpenSSL API permits.
- This is **not** a production password manager. It does not protect against memory scraping, side-channel attacks or sophisticated malware. It illustrates the architecture and process described in the project report.

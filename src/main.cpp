// GUI version of the Desktop Password Manager.
// Uses the Windows API directly (no extra libraries needed) to give a real
// window with Log In / Log Out / Recover Password buttons, a show-password
// checkbox, a minimum password strength rule, and a Light/Dark theme toggle.
// All vault/crypto logic is unchanged and reused from vault.cpp / crypto.cpp.

#include "vault.hpp"
#include "crypto.hpp"

#include <windows.h>
#include <dwmapi.h>
#include <string>
#include <cstdio>
#include <cctype>
#include <vector>
#include <algorithm>
#include <stdexcept>

using namespace pm;

namespace {

    Vault* g_vault = nullptr;
    HWND g_hMainWindow = nullptr;
    HFONT g_hUiFont = nullptr;
    HFONT g_hHeadingFont = nullptr;

    HWND g_hPasswordEdit = nullptr;
    HWND g_hConfirmPasswordEdit = nullptr;
    HWND g_hConfirmPasswordLabel = nullptr;
    HWND g_hShowPasswordCheck = nullptr;
    HWND g_hLoginBtn = nullptr;
    HWND g_hCreateAccountBtn = nullptr;
    HWND g_hLogoutBtn = nullptr;
    HWND g_hRecoverBtn = nullptr;
    HWND g_hThemeToggleBtn = nullptr;
    HWND g_hStatusStatic = nullptr;
    HWND g_hListBox = nullptr;
    HWND g_hLoginLabel = nullptr;
    HWND g_hListBtn = nullptr;
    HWND g_hAddBtn = nullptr;
    HWND g_hEditBtn = nullptr;
    HWND g_hDeleteBtn = nullptr;
    HWND g_hSearchEdit = nullptr;
    HWND g_hSearchBtn = nullptr;
    HWND g_hViewBtn = nullptr;
    HWND g_hExitBtn = nullptr;
    HWND g_hServiceEdit = nullptr;
    HWND g_hUsernameEdit = nullptr;
    HWND g_hCredentialPasswordEdit = nullptr;
    HWND g_hCredentialShowCheck = nullptr;
    HWND g_hNotesEdit = nullptr;
    HWND g_hGeneratePasswordBtn = nullptr;
    HWND g_hSaveBtn = nullptr;
    HWND g_hCancelBtn = nullptr;
    HWND g_hFormLabel = nullptr;
    HWND g_hServiceLabel = nullptr;
    HWND g_hUsernameLabel = nullptr;
    HWND g_hCredentialPasswordLabel = nullptr;
    HWND g_hNotesLabel = nullptr;
    std::vector<int> g_displayedCredentialIds;
    int g_editingCredentialId = 0;

    HBRUSH g_hBgBrush = nullptr;
    HBRUSH g_hEditBrush = nullptr;

    constexpr int ID_PASSWORD_EDIT = 101;
    constexpr int ID_LOGIN_BTN = 102;
    constexpr int ID_LOGOUT_BTN = 103;
    constexpr int ID_RECOVER_BTN = 104;
    constexpr int ID_STATUS_STATIC = 105;
    constexpr int ID_LISTBOX = 106;
    constexpr int ID_SHOW_PASSWORD_CHECK = 107;
    constexpr int ID_THEME_TOGGLE_BTN = 108;
    constexpr int ID_LIST_BTN = 109;
    constexpr int ID_ADD_BTN = 110;
    constexpr int ID_EDIT_BTN = 111;
    constexpr int ID_DELETE_BTN = 112;
    constexpr int ID_SEARCH_EDIT = 113;
    constexpr int ID_SEARCH_BTN = 114;
    constexpr int ID_VIEW_BTN = 115;
    constexpr int ID_EXIT_BTN = 116;
    constexpr int ID_SERVICE_EDIT = 117;
    constexpr int ID_USERNAME_EDIT = 118;
    constexpr int ID_CREDENTIAL_PASSWORD_EDIT = 119;
    constexpr int ID_NOTES_EDIT = 120;
    constexpr int ID_SAVE_BTN = 121;
    constexpr int ID_CANCEL_BTN = 122;
    constexpr int ID_FORM_LABEL = 123;
    constexpr int ID_GENERATE_PASSWORD_BTN = 124;
    constexpr int ID_CREDENTIAL_SHOW_CHECK = 125;
    constexpr int ID_CREATE_ACCOUNT_BTN = 126;
    constexpr int ID_CONFIRM_PASSWORD_EDIT = 127;

    bool g_isDarkMode = true;

    COLORREF g_colorBg = RGB(25, 29, 37);
    COLORREF g_colorEditBg = RGB(37, 43, 53);
    COLORREF g_colorText = RGB(232, 237, 245);

    const COLORREF COLOR_LOGIN = RGB(35, 150, 115);
    const COLORREF COLOR_LOGOUT = RGB(184, 76, 77);
    const COLORREF COLOR_RECOVER = RGB(191, 105, 43);
    const COLORREF COLOR_TOGGLE = RGB(62, 91, 125);
    const COLORREF COLOR_ACTION = RGB(48, 105, 150);
    const COLORREF COLOR_DISABLED = RGB(90, 90, 90);

    enum class CredentialForm { Hidden, Add, Edit };
    CredentialForm g_credentialForm = CredentialForm::Hidden;
    bool g_createAccountMode = false;

    void SetControlVisible(HWND control, bool visible) {
        if (control) ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
    }

    void SetStatus(const std::wstring& text) {
        SetWindowTextW(g_hStatusStatic, text.c_str());
        RedrawWindow(g_hMainWindow, nullptr, nullptr,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }

    std::wstring Utf8ToWide(const std::string& s) {
        if (s.empty()) return L"";
        int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], size);
        return result;
    }

    std::string WideToUtf8(const std::wstring& s) {
        if (s.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], size, nullptr, nullptr);
        return result;
    }

    // Master password rule: at least 12 characters, with at least one
    // uppercase letter, one lowercase letter, one number, and one special character.
    bool IsPasswordStrong(const std::string& pw) {
        if (pw.size() < 12) return false;
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (unsigned char c : pw) {
            if (std::isupper(c)) hasUpper = true;
            else if (std::islower(c)) hasLower = true;
            else if (std::isdigit(c)) hasDigit = true;
            else hasSpecial = true;
        }
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    void WipeCredential(Credential& credential) {
        secure_wipe(credential.password);
        secure_wipe(credential.username);
        secure_wipe(credential.notes);
        secure_wipe(credential.service);
    }

    std::wstring GetControlText(HWND control) {
        int length = GetWindowTextLengthW(control);
        std::wstring text(static_cast<size_t>(length) + 1, L'\0');
        GetWindowTextW(control, &text[0], length + 1);
        text.resize(static_cast<size_t>(length));
        return text;
    }

    std::string GetControlTextUtf8(HWND control) {
        std::wstring wideText = GetControlText(control);
        std::string text = WideToUtf8(wideText);
        if (!wideText.empty()) {
            SecureZeroMemory(&wideText[0], wideText.size() * sizeof(wchar_t));
        }
        return text;
    }

    int GetSelectedCredentialId() {
        LRESULT selected = SendMessageW(g_hListBox, LB_GETCURSEL, 0, 0);
        if (selected == LB_ERR || static_cast<size_t>(selected) >= g_displayedCredentialIds.size()) {
            MessageBoxW(nullptr, L"Select a credential first.", L"Password Manager",
                MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        return g_displayedCredentialIds[static_cast<size_t>(selected)];
    }

    void RefreshCredentialList(const std::vector<Credential>* filtered = nullptr) {
        SendMessageW(g_hListBox, LB_RESETCONTENT, 0, 0);
        g_displayedCredentialIds.clear();
        if (!g_vault->is_unlocked()) return;

        std::vector<Credential> entries = filtered ? *filtered : g_vault->list();
        for (auto& c : entries) {
            std::wstring line = L"#" + std::to_wstring(c.id) + L"  " +
                Utf8ToWide(c.service) + L"  (" + Utf8ToWide(c.username) + L")";
            SendMessageW(g_hListBox, LB_ADDSTRING, 0, (LPARAM)line.c_str());
            g_displayedCredentialIds.push_back(c.id);
            WipeCredential(c);
        }
    }

    void ClearPasswordField() {
        SetWindowTextW(g_hPasswordEdit, L"");
    }

    void ResetPasswordVisibility() {
        SendMessageW(g_hShowPasswordCheck, BM_SETCHECK, BST_UNCHECKED, 0);
        SendMessageW(g_hPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'*', 0);
        InvalidateRect(g_hPasswordEdit, nullptr, TRUE);
    }

    void LayoutForState(bool unlocked) {
        if (!g_hMainWindow) return;
        SetWindowPos(g_hMainWindow, nullptr, 0, 0,
            unlocked ? 800 : 500, unlocked ? 545 : 300,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

        if (!unlocked) {
            SetWindowPos(g_hMainWindow, nullptr, 0, 0,
                500, g_createAccountMode ? 390 : 300,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            MoveWindow(g_hStatusStatic, 24, 18, 155, 24, TRUE);
            MoveWindow(g_hRecoverBtn, 190, 14, 145, 32, TRUE);
            MoveWindow(g_hThemeToggleBtn, 350, 14, 120, 32, TRUE);
            MoveWindow(g_hLoginLabel, 24, 68, 240, 22, TRUE);
            MoveWindow(g_hPasswordEdit, 24, 94, 440, 28, TRUE);
            MoveWindow(g_hShowPasswordCheck, 24, 130, 180, 24, TRUE);
            MoveWindow(g_hConfirmPasswordLabel, 24, 168, 240, 22, TRUE);
            MoveWindow(g_hConfirmPasswordEdit, 24, 194, 440, 28, TRUE);
            MoveWindow(g_hLoginBtn, 24, g_createAccountMode ? 242 : 168, 130, 36, TRUE);
            MoveWindow(g_hCreateAccountBtn, g_createAccountMode ? 166 : 166,
                g_createAccountMode ? 242 : 168, 160, 36, TRUE);
            return;
        }

        MoveWindow(g_hStatusStatic, 24, 17, 430, 26, TRUE);
        MoveWindow(g_hLogoutBtn, 490, 14, 110, 32, TRUE);
        MoveWindow(g_hExitBtn, 610, 14, 72, 32, TRUE);
        MoveWindow(g_hThemeToggleBtn, 692, 14, 90, 32, TRUE);
        MoveWindow(g_hListBtn, 20, 58, 100, 32, TRUE);
        MoveWindow(g_hAddBtn, 130, 58, 72, 32, TRUE);
        MoveWindow(g_hEditBtn, 212, 58, 72, 32, TRUE);
        MoveWindow(g_hDeleteBtn, 294, 58, 82, 32, TRUE);
        MoveWindow(g_hViewBtn, 386, 58, 104, 32, TRUE);
        MoveWindow(g_hSearchEdit, 502, 62, 170, 26, TRUE);
        MoveWindow(g_hSearchBtn, 682, 58, 100, 32, TRUE);
        MoveWindow(g_hListBox, 20, 104, 762, 210, TRUE);
        MoveWindow(g_hFormLabel, 20, 326, 300, 24, TRUE);
        MoveWindow(g_hServiceLabel, 20, 363, 60, 22, TRUE);
        MoveWindow(g_hServiceEdit, 80, 359, 208, 26, TRUE);
        MoveWindow(g_hUsernameLabel, 302, 363, 76, 22, TRUE);
        MoveWindow(g_hUsernameEdit, 378, 359, 208, 26, TRUE);
        MoveWindow(g_hSaveBtn, 620, 357, 162, 34, TRUE);
        MoveWindow(g_hCredentialPasswordLabel, 20, 405, 60, 22, TRUE);
        MoveWindow(g_hCredentialPasswordEdit, 80, 401, 245, 26, TRUE);
        MoveWindow(g_hGeneratePasswordBtn, 340, 398, 100, 32, TRUE);
        MoveWindow(g_hCredentialShowCheck, 450, 402, 140, 24, TRUE);
        MoveWindow(g_hNotesLabel, 20, 447, 60, 22, TRUE);
        MoveWindow(g_hNotesEdit, 80, 443, 506, 26, TRUE);
        MoveWindow(g_hCancelBtn, 620, 441, 162, 34, TRUE);
    }

    void UpdateButtonStates() {
        bool unlocked = g_vault->is_unlocked();
        EnableWindow(g_hLoginBtn, !unlocked);
        EnableWindow(g_hPasswordEdit, !unlocked);
        InvalidateRect(g_hLoginBtn, nullptr, TRUE);

        SetControlVisible(g_hLoginLabel, !unlocked);
        SetControlVisible(g_hPasswordEdit, !unlocked);
        SetControlVisible(g_hShowPasswordCheck, !unlocked);
        SetControlVisible(g_hLoginBtn, !unlocked);
        SetControlVisible(g_hCreateAccountBtn, !unlocked);
        SetControlVisible(g_hConfirmPasswordLabel, !unlocked && g_createAccountMode);
        SetControlVisible(g_hConfirmPasswordEdit, !unlocked && g_createAccountMode);
        SetControlVisible(g_hRecoverBtn, !unlocked);
        SetControlVisible(g_hThemeToggleBtn, true);
        SetControlVisible(g_hLogoutBtn, unlocked);
        SetControlVisible(g_hListBtn, unlocked);
        SetControlVisible(g_hAddBtn, unlocked);
        SetControlVisible(g_hEditBtn, unlocked);
        SetControlVisible(g_hDeleteBtn, unlocked);
        SetControlVisible(g_hSearchEdit, unlocked);
        SetControlVisible(g_hSearchBtn, unlocked);
        SetControlVisible(g_hViewBtn, unlocked);
        SetControlVisible(g_hExitBtn, unlocked);
        SetControlVisible(g_hListBox, unlocked);
        SetControlVisible(g_hStatusStatic, true);
        if (!unlocked) {
            g_credentialForm = CredentialForm::Hidden;
            SetControlVisible(g_hFormLabel, false);
            SetControlVisible(g_hServiceLabel, false);
            SetControlVisible(g_hUsernameLabel, false);
            SetControlVisible(g_hCredentialPasswordLabel, false);
            SetControlVisible(g_hNotesLabel, false);
            SetControlVisible(g_hServiceEdit, false);
            SetControlVisible(g_hUsernameEdit, false);
            SetControlVisible(g_hCredentialPasswordEdit, false);
            SetControlVisible(g_hCredentialShowCheck, false);
            SetControlVisible(g_hGeneratePasswordBtn, false);
            SetControlVisible(g_hNotesEdit, false);
            SetControlVisible(g_hSaveBtn, false);
            SetControlVisible(g_hCancelBtn, false);
        }
            LayoutForState(unlocked);
    }

    std::string GetPasswordFieldText() {
        wchar_t buf[256];
        GetWindowTextW(g_hPasswordEdit, buf, 256);
        return WideToUtf8(buf);
    }

    void OnLoginClicked() {
        if (g_createAccountMode) {
            std::string password = GetPasswordFieldText();
            std::string confirmation = GetControlTextUtf8(g_hConfirmPasswordEdit);
            if (password.empty() || confirmation.empty()) {
                MessageBoxW(nullptr, L"Enter and confirm your new master password.",
                    L"Create Account", MB_OK | MB_ICONWARNING);
            } else if (!IsPasswordStrong(password)) {
                MessageBoxW(nullptr,
                    L"Master password must be at least 12 characters long and "
                    L"include uppercase and lowercase letters, a number, and a special character.",
                    L"Password too weak", MB_OK | MB_ICONWARNING);
            } else if (password != confirmation) {
                MessageBoxW(nullptr, L"The passwords do not match.", L"Create Account",
                    MB_OK | MB_ICONWARNING);
            } else {
                try {
                    if (g_vault->exists()) {
                        MessageBoxW(nullptr, L"An account already exists for this local vault. "
                            L"Log in with its master password instead.",
                            L"Account already exists", MB_OK | MB_ICONINFORMATION);
                    } else {
                        g_vault->create(password);
                        g_createAccountMode = false;
                        ClearPasswordField();
                        SetWindowTextW(g_hConfirmPasswordEdit, L"");
                        UpdateButtonStates();
                        RefreshCredentialList();
                        SetStatus(L"Logged in.");
                    }
                } catch (const std::exception& e) {
                    MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error",
                        MB_OK | MB_ICONERROR);
                }
            }
            secure_wipe(password);
            secure_wipe(confirmation);
            return;
        }

        std::string pw = GetPasswordFieldText();
        if (pw.empty()) {
            MessageBoxW(nullptr, L"Please enter a password.", L"Password Manager",
                MB_OK | MB_ICONWARNING);
            secure_wipe(pw);
            return;
        }

        try {
            if (!g_vault->exists()) {
                if (!IsPasswordStrong(pw)) {
                    MessageBoxW(nullptr,
                        L"Master password must be at least 12 characters long and "
                        L"include at least one uppercase letter, one lowercase "
                        L"letter, one number, and one special character "
                        L"(e.g. ! @ # $ %).",
                        L"Password too weak", MB_OK | MB_ICONWARNING);
                    secure_wipe(pw);
                    return;
                }
                int confirm = MessageBoxW(nullptr,
                    L"No vault found yet. Create a new one with this master password?",
                    L"Create Vault", MB_YESNO | MB_ICONQUESTION);
                if (confirm != IDYES) {
                    secure_wipe(pw);
                    return;
                }
                g_vault->create(pw);
            }
            else {
                if (!g_vault->unlock(pw)) {
                    MessageBoxW(nullptr, L"Incorrect master password.", L"Login failed",
                        MB_OK | MB_ICONERROR);
                    secure_wipe(pw);
                    return;
                }
            }
            ClearPasswordField();
            ResetPasswordVisibility();
            UpdateButtonStates();
            RefreshCredentialList();
            SetStatus(L"Logged in.");
        }
        catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
        secure_wipe(pw);
    }

    void OnCreateAccountClicked() {
        if (g_vault->exists()) {
            MessageBoxW(nullptr, L"This app currently supports one account per local vault. "
                L"Log in with the existing master password, or use Recover Password to reset the vault.",
                L"Account already exists", MB_OK | MB_ICONINFORMATION);
            return;
        }
        g_createAccountMode = !g_createAccountMode;
        ClearPasswordField();
        SetWindowTextW(g_hConfirmPasswordEdit, L"");
        SetWindowTextW(g_hLoginBtn, g_createAccountMode ? L"Create Account" : L"Log In");
        SetWindowTextW(g_hCreateAccountBtn, g_createAccountMode ? L"Back to Log In" : L"Create Account");
        SetStatus(g_createAccountMode
            ? L"Create an account."
            : L"Not logged in.");
        UpdateButtonStates();
        if (g_createAccountMode) SetFocus(g_hPasswordEdit);
    }

    void ClearCredentialForm() {
        SetWindowTextW(g_hServiceEdit, L"");
        SetWindowTextW(g_hUsernameEdit, L"");
        SetWindowTextW(g_hCredentialPasswordEdit, L"");
        SetWindowTextW(g_hNotesEdit, L"");
    }

    std::string GenerateStrongPassword() {
        constexpr char upper[] = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        constexpr char lower[] = "abcdefghijkmnopqrstuvwxyz";
        constexpr char digits[] = "23456789";
        constexpr char special[] = "!@#$%&*+-=?_";
        constexpr char all[] =
            "ABCDEFGHJKLMNPQRSTUVWXYZ"
            "abcdefghijkmnopqrstuvwxyz"
            "23456789!@#$%&*+-=?_";

        std::vector<uint8_t> entropy = random_bytes(128);
        size_t entropyIndex = 0;
        auto randomIndex = [&entropy, &entropyIndex](size_t count) {
            const size_t limit = 256 - (256 % count);
            while (entropyIndex < entropy.size()) {
                uint8_t value = entropy[entropyIndex++];
                if (value < limit) return static_cast<size_t>(value) % count;
            }
            throw std::runtime_error("Could not generate password randomness");
        };

        std::string password;
        try {
            password.reserve(20);
            password.push_back(upper[randomIndex(sizeof(upper) - 1)]);
            password.push_back(lower[randomIndex(sizeof(lower) - 1)]);
            password.push_back(digits[randomIndex(sizeof(digits) - 1)]);
            password.push_back(special[randomIndex(sizeof(special) - 1)]);
            for (size_t i = 4; i < 20; ++i) {
                password.push_back(all[randomIndex(sizeof(all) - 1)]);
            }
            for (size_t i = password.size() - 1; i > 0; --i) {
                std::swap(password[i], password[randomIndex(i + 1)]);
            }
        } catch (...) {
            secure_wipe(password);
            secure_wipe(entropy);
            throw;
        }
        secure_wipe(entropy);
        return password;
    }

    void OnGeneratePassword() {
        try {
            std::string password = GenerateStrongPassword();
            std::wstring widePassword = Utf8ToWide(password);
            SetWindowTextW(g_hCredentialPasswordEdit, widePassword.c_str());
            SetStatus(L"Generated a strong 20-character password.");
            if (!widePassword.empty()) {
                SecureZeroMemory(&widePassword[0], widePassword.size() * sizeof(wchar_t));
            }
            secure_wipe(password);
        } catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Password generation failed",
                MB_OK | MB_ICONERROR);
        }
    }

    void OnCredentialPasswordVisibilityToggled() {
        bool show = SendMessageW(g_hCredentialShowCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
        SendMessageW(g_hCredentialPasswordEdit, EM_SETPASSWORDCHAR,
            show ? 0 : static_cast<WPARAM>(L'*'), 0);
        InvalidateRect(g_hCredentialPasswordEdit, nullptr, TRUE);
    }

    void HideCredentialForm();

    void ShowCredentialForm(CredentialForm form) {
        if (!g_vault->is_unlocked()) return;
        ClearCredentialForm();
        SendMessageW(g_hCredentialShowCheck, BM_SETCHECK, BST_UNCHECKED, 0);
        SendMessageW(g_hCredentialPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'*', 0);
        InvalidateRect(g_hCredentialPasswordEdit, nullptr, TRUE);
        g_editingCredentialId = 0;
        g_credentialForm = form;

        if (form == CredentialForm::Edit) {
            int id = GetSelectedCredentialId();
            if (!id) {
                HideCredentialForm();
                return;
            }
            auto credential = g_vault->get(id);
            if (!credential) {
                MessageBoxW(nullptr, L"The selected credential no longer exists.",
                    L"Password Manager", MB_OK | MB_ICONWARNING);
                HideCredentialForm();
                return;
            }
            g_editingCredentialId = id;
            SetWindowTextW(g_hServiceEdit, Utf8ToWide(credential->service).c_str());
            SetWindowTextW(g_hUsernameEdit, Utf8ToWide(credential->username).c_str());
            SetWindowTextW(g_hCredentialPasswordEdit, Utf8ToWide(credential->password).c_str());
            SetWindowTextW(g_hNotesEdit, Utf8ToWide(credential->notes).c_str());
            WipeCredential(*credential);
        }

        SetWindowTextW(g_hFormLabel,
            form == CredentialForm::Add ? L"Add credential" : L"Edit selected credential");
        SetControlVisible(g_hFormLabel, true);
        SetControlVisible(g_hServiceLabel, true);
        SetControlVisible(g_hUsernameLabel, true);
        SetControlVisible(g_hCredentialPasswordLabel, true);
        SetControlVisible(g_hNotesLabel, true);
        SetControlVisible(g_hServiceEdit, true);
        SetControlVisible(g_hUsernameEdit, true);
        SetControlVisible(g_hCredentialPasswordEdit, true);
        SetControlVisible(g_hCredentialShowCheck, true);
        SetControlVisible(g_hGeneratePasswordBtn, true);
        SetControlVisible(g_hNotesEdit, true);
        SetControlVisible(g_hSaveBtn, true);
        SetControlVisible(g_hCancelBtn, true);
        SetFocus(g_hServiceEdit);
    }

    void HideCredentialForm() {
        ClearCredentialForm();
        SendMessageW(g_hCredentialShowCheck, BM_SETCHECK, BST_UNCHECKED, 0);
        SendMessageW(g_hCredentialPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'*', 0);
        InvalidateRect(g_hCredentialPasswordEdit, nullptr, TRUE);
        g_editingCredentialId = 0;
        g_credentialForm = CredentialForm::Hidden;
        SetControlVisible(g_hFormLabel, false);
        SetControlVisible(g_hServiceLabel, false);
        SetControlVisible(g_hUsernameLabel, false);
        SetControlVisible(g_hCredentialPasswordLabel, false);
        SetControlVisible(g_hNotesLabel, false);
        SetControlVisible(g_hServiceEdit, false);
        SetControlVisible(g_hUsernameEdit, false);
        SetControlVisible(g_hCredentialPasswordEdit, false);
        SetControlVisible(g_hCredentialShowCheck, false);
        SetControlVisible(g_hGeneratePasswordBtn, false);
        SetControlVisible(g_hNotesEdit, false);
        SetControlVisible(g_hSaveBtn, false);
        SetControlVisible(g_hCancelBtn, false);
    }

    void OnSaveCredential() {
        if (g_credentialForm == CredentialForm::Hidden) return;
        std::string service = GetControlTextUtf8(g_hServiceEdit);
        std::string username = GetControlTextUtf8(g_hUsernameEdit);
        std::string password = GetControlTextUtf8(g_hCredentialPasswordEdit);
        std::string notes = GetControlTextUtf8(g_hNotesEdit);
        if (service.empty()) {
            MessageBoxW(nullptr, L"Service name cannot be empty.", L"Password Manager",
                MB_OK | MB_ICONWARNING);
            secure_wipe(password);
            secure_wipe(username);
            secure_wipe(notes);
            secure_wipe(service);
            return;
        }

        try {
            if (g_credentialForm == CredentialForm::Add) {
                g_vault->add(service, username, password, notes);
                SetStatus(L"Credential added.");
            } else if (!g_vault->update(g_editingCredentialId, service, username, password, notes)) {
                MessageBoxW(nullptr, L"The selected credential could not be found.",
                    L"Password Manager", MB_OK | MB_ICONWARNING);
                secure_wipe(password);
                secure_wipe(username);
                secure_wipe(notes);
                secure_wipe(service);
                return;
            } else {
                SetStatus(L"Credential updated.");
            }
            HideCredentialForm();
            RefreshCredentialList();
        }
        catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
        secure_wipe(password);
        secure_wipe(username);
        secure_wipe(notes);
        secure_wipe(service);
    }

    void OnDeleteCredential() {
        int id = GetSelectedCredentialId();
        if (!id) return;
        auto credential = g_vault->get(id);
        if (!credential) {
            MessageBoxW(nullptr, L"The selected credential no longer exists.",
                L"Password Manager", MB_OK | MB_ICONWARNING);
            return;
        }
        std::wstring prompt = L"Permanently delete the credential for \"" +
            Utf8ToWide(credential->service) + L"\"?";
        WipeCredential(*credential);
        if (MessageBoxW(nullptr, prompt.c_str(), L"Delete credential",
            MB_YESNO | MB_ICONWARNING) != IDYES) return;
        try {
            if (g_vault->remove(id)) {
                HideCredentialForm();
                RefreshCredentialList();
                SetStatus(L"Credential deleted.");
            }
        } catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }

    void OnSearchCredentials() {
        std::string query = GetControlTextUtf8(g_hSearchEdit);
        try {
            auto results = g_vault->search(query);
            RefreshCredentialList(&results);
            for (auto& credential : results) WipeCredential(credential);
            SetStatus(L"Search complete.");
        } catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
        secure_wipe(query);
    }

    void OnViewCredential() {
        int id = GetSelectedCredentialId();
        if (!id) return;
        auto credential = g_vault->get(id);
        if (!credential) {
            MessageBoxW(nullptr, L"The selected credential no longer exists.",
                L"Password Manager", MB_OK | MB_ICONWARNING);
            return;
        }
        std::wstring details = L"Service: " + Utf8ToWide(credential->service) +
            L"\nUsername: " + Utf8ToWide(credential->username) +
            L"\nPassword: " + Utf8ToWide(credential->password) +
            L"\nNotes: " + Utf8ToWide(credential->notes);
        WipeCredential(*credential);
        MessageBoxW(nullptr, details.c_str(), L"Credential details", MB_OK | MB_ICONINFORMATION);
        if (!details.empty()) SecureZeroMemory(&details[0], details.size() * sizeof(wchar_t));
        details.clear();
    }

    void OnLogoutClicked() {
        if (!g_vault->is_unlocked()) return;
        g_vault->lock();
        SetWindowTextW(g_hSearchEdit, L"");
        HideCredentialForm();
        ClearPasswordField();
        ResetPasswordVisibility();
        RefreshCredentialList();
        UpdateButtonStates();
        SetStatus(L"ENTER");
    }

    void OnRecoverClicked() {
        if (!g_vault->exists()) {
            MessageBoxW(nullptr,
                L"There is no vault yet, so there is nothing to recover.\n"
                L"Just enter a password and click \"Log In\" to create one.",
                L"Recover Password", MB_OK | MB_ICONINFORMATION);
            return;
        }

        int choice = MessageBoxW(nullptr,
            L"For security, the master password is never stored anywhere -- "
            L"not even in an encrypted form that could be reversed. This means "
            L"it genuinely cannot be recovered if it's forgotten.\n\n"
            L"The only option is to reset the vault, which permanently deletes "
            L"ALL saved credentials and lets you start over with a new master "
            L"password.\n\nDo you want to reset the vault now?",
            L"Recover Password", MB_YESNO | MB_ICONWARNING);
        if (choice != IDYES) return;

        int confirm2 = MessageBoxW(nullptr,
            L"This cannot be undone. All stored credentials will be lost.\n"
            L"Continue with reset?",
            L"Confirm Reset", MB_YESNO | MB_ICONWARNING);
        if (confirm2 != IDYES) return;

        if (g_vault->is_unlocked()) {
            g_vault->lock();
        }
        HideCredentialForm();
        SetWindowTextW(g_hSearchEdit, L"");
        std::remove("vault.dat");

        delete g_vault;
        g_vault = new Vault("vault.dat");

        ClearPasswordField();
        ResetPasswordVisibility();
        RefreshCredentialList();
        UpdateButtonStates();
        SetStatus(L"ENTER");
    }

    void OnShowPasswordToggled() {
        bool checked = (SendMessageW(g_hShowPasswordCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
        SendMessageW(g_hPasswordEdit, EM_SETPASSWORDCHAR, checked ? 0 : (WPARAM)L'*', 0);
        InvalidateRect(g_hPasswordEdit, nullptr, TRUE);
    }

    // Switches the whole window between dark and light colour schemes.
    void ApplyTheme(HWND hwnd, bool dark) {
        g_isDarkMode = dark;

        if (dark) {
            g_colorBg = RGB(25, 29, 37);
            g_colorEditBg = RGB(37, 43, 53);
            g_colorText = RGB(232, 237, 245);
        }
        else {
            g_colorBg = RGB(241, 244, 248);
            g_colorEditBg = RGB(255, 255, 255);
            g_colorText = RGB(34, 44, 58);
        }

        if (g_hBgBrush) DeleteObject(g_hBgBrush);
        if (g_hEditBrush) DeleteObject(g_hEditBrush);
        g_hBgBrush = CreateSolidBrush(g_colorBg);
        g_hEditBrush = CreateSolidBrush(g_colorEditBg);

        // Update the window class background so WM_ERASEBKGND uses the new colour.
        SetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)g_hBgBrush);

        SetWindowTextW(g_hThemeToggleBtn, dark ? L"Light Mode" : L"Dark Mode");

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
        BOOL darkTitleBar = dark ? TRUE : FALSE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            &darkTitleBar, sizeof(darkTitleBar));

        RedrawWindow(hwnd, nullptr, nullptr,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }

    COLORREF ColorForButton(int id, bool disabled) {
        if (disabled) return COLOR_DISABLED;
        switch (id) {
        case ID_LOGIN_BTN:        return COLOR_LOGIN;
        case ID_CREATE_ACCOUNT_BTN: return COLOR_ACTION;
        case ID_LOGOUT_BTN:       return COLOR_LOGOUT;
        case ID_RECOVER_BTN:      return COLOR_RECOVER;
        case ID_THEME_TOGGLE_BTN: return COLOR_TOGGLE;
        case ID_DELETE_BTN:       return COLOR_LOGOUT;
        case ID_SAVE_BTN:         return COLOR_LOGIN;
        default:                  return COLOR_ACTION;
        }
    }

    BOOL CALLBACK SetChildFont(HWND child, LPARAM font) {
        SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(font), TRUE);
        return TRUE;
    }

    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE: {
            g_hMainWindow = hwnd;
            auto makeButton = [hwnd](const wchar_t* text, int id, int x, int y, int width) {
                return CreateWindowW(L"BUTTON", text,
                    WS_CHILD | BS_OWNERDRAW,
                    x, y, width, 32, hwnd, (HMENU)(intptr_t)id, nullptr, nullptr);
            };
            auto makeLabel = [hwnd](const wchar_t* text, int x, int y, int width) {
                return CreateWindowW(L"STATIC", text, WS_CHILD,
                    x, y, width, 22, hwnd, nullptr, nullptr, nullptr);
            };
            auto makeEdit = [hwnd](int id, int x, int y, int width, DWORD extraStyle = 0) {
                return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                    WS_CHILD | ES_AUTOHSCROLL | extraStyle,
                    x, y, width, 24, hwnd, (HMENU)(intptr_t)id, nullptr, nullptr);
            };

            g_hLoginLabel = makeLabel(L"Master password:", 20, 55, 200);
            g_hThemeToggleBtn = makeButton(L"Light Mode", ID_THEME_TOGGLE_BTN, 680, 16, 120);
            g_hRecoverBtn = makeButton(L"Recover Password", ID_RECOVER_BTN, 500, 16, 160);
            g_hPasswordEdit = makeEdit(ID_PASSWORD_EDIT, 20, 80, 300, ES_PASSWORD);
            g_hShowPasswordCheck = CreateWindowW(L"BUTTON", L"Show password",
                WS_CHILD | BS_AUTOCHECKBOX, 20, 110, 150, 22, hwnd,
                (HMENU)(intptr_t)ID_SHOW_PASSWORD_CHECK, nullptr, nullptr);
            g_hLoginBtn = makeButton(L"Log In", ID_LOGIN_BTN, 20, 145, 100);
            g_hCreateAccountBtn = makeButton(L"Create Account", ID_CREATE_ACCOUNT_BTN, 130, 145, 150);
            g_hConfirmPasswordLabel = makeLabel(L"Confirm master password:", 24, 168, 240);
            g_hConfirmPasswordEdit = makeEdit(ID_CONFIRM_PASSWORD_EDIT, 24, 194, 440, ES_PASSWORD);
            g_hLogoutBtn = makeButton(L"Log Out", ID_LOGOUT_BTN, 20, 110, 100);
            g_hExitBtn = makeButton(L"Exit", ID_EXIT_BTN, 130, 110, 100);

            g_hStatusStatic = CreateWindowW(L"STATIC", L"Not logged in.",
                WS_CHILD | WS_VISIBLE, 20, 20, 450, 24, hwnd,
                (HMENU)(intptr_t)ID_STATUS_STATIC, nullptr, nullptr);
            g_hListBtn = makeButton(L"List credentials", ID_LIST_BTN, 20, 65, 100);
            g_hAddBtn = makeButton(L"Add", ID_ADD_BTN, 130, 65, 85);
            g_hEditBtn = makeButton(L"Edit", ID_EDIT_BTN, 225, 65, 85);
            g_hDeleteBtn = makeButton(L"Delete", ID_DELETE_BTN, 320, 65, 85);
            g_hViewBtn = makeButton(L"View details", ID_VIEW_BTN, 415, 65, 85);
            g_hSearchEdit = makeEdit(ID_SEARCH_EDIT, 510, 69, 190);
            g_hSearchBtn = makeButton(L"Search", ID_SEARCH_BTN, 710, 65, 90);

            g_hListBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                WS_CHILD | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                20, 155, 780, 255, hwnd, (HMENU)(intptr_t)ID_LISTBOX, nullptr, nullptr);

            g_hFormLabel = makeLabel(L"", 20, 425, 300);
            g_hServiceLabel = makeLabel(L"Service:", 20, 455, 65);
            g_hServiceEdit = makeEdit(ID_SERVICE_EDIT, 85, 452, 240);
            g_hUsernameLabel = makeLabel(L"Username:", 345, 455, 75);
            g_hUsernameEdit = makeEdit(ID_USERNAME_EDIT, 420, 452, 235);
            g_hCredentialPasswordLabel = makeLabel(L"Password:", 20, 490, 65);
            g_hCredentialPasswordEdit = makeEdit(ID_CREDENTIAL_PASSWORD_EDIT,
                85, 487, 240, ES_PASSWORD);
            g_hNotesLabel = makeLabel(L"Notes:", 345, 490, 75);
            g_hNotesEdit = makeEdit(ID_NOTES_EDIT, 420, 487, 235);
            g_hGeneratePasswordBtn = makeButton(L"Generate", ID_GENERATE_PASSWORD_BTN, 0, 0, 100);
            g_hCredentialShowCheck = CreateWindowW(L"BUTTON", L"Show password",
                WS_CHILD | BS_AUTOCHECKBOX, 0, 0, 140, 24, hwnd,
                (HMENU)(intptr_t)ID_CREDENTIAL_SHOW_CHECK, nullptr, nullptr);
            g_hSaveBtn = makeButton(L"Save", ID_SAVE_BTN, 675, 452, 125);
            g_hCancelBtn = makeButton(L"Cancel", ID_CANCEL_BTN, 675, 487, 125);

            g_hUiFont = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            g_hHeadingFont = CreateFontW(-18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            EnumChildWindows(hwnd, SetChildFont, reinterpret_cast<LPARAM>(g_hUiFont));
            SendMessageW(g_hStatusStatic, WM_SETFONT,
                reinterpret_cast<WPARAM>(g_hHeadingFont), TRUE);

            UpdateButtonStates();

            if (!g_vault->exists()) {
                SetStatus(L"No account yet.");
            }
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
            case ID_LOGIN_BTN:        OnLoginClicked();   break;
            case ID_CREATE_ACCOUNT_BTN: OnCreateAccountClicked(); break;
            case ID_LOGOUT_BTN:       OnLogoutClicked();  break;
            case ID_RECOVER_BTN:      OnRecoverClicked(); break;
            case ID_THEME_TOGGLE_BTN: ApplyTheme(hwnd, !g_isDarkMode); break;
            case ID_LIST_BTN:
                SetWindowTextW(g_hSearchEdit, L"");
                RefreshCredentialList();
                SetStatus(L"All saved credentials.");
                break;
            case ID_ADD_BTN:          ShowCredentialForm(CredentialForm::Add); break;
            case ID_EDIT_BTN:         ShowCredentialForm(CredentialForm::Edit); break;
            case ID_DELETE_BTN:       OnDeleteCredential(); break;
            case ID_SEARCH_BTN:       OnSearchCredentials(); break;
            case ID_VIEW_BTN:         OnViewCredential(); break;
            case ID_SAVE_BTN:         OnSaveCredential(); break;
            case ID_CANCEL_BTN:       HideCredentialForm(); break;
            case ID_GENERATE_PASSWORD_BTN: OnGeneratePassword(); break;
            case ID_EXIT_BTN:         PostMessageW(hwnd, WM_CLOSE, 0, 0); break;
            case ID_SHOW_PASSWORD_CHECK:
                if (HIWORD(wParam) == BN_CLICKED) OnShowPasswordToggled();
                break;
            case ID_CREDENTIAL_SHOW_CHECK:
                if (HIWORD(wParam) == BN_CLICKED) OnCredentialPasswordVisibilityToggled();
                break;
            case ID_LISTBOX:
                if (HIWORD(wParam) == LBN_DBLCLK) OnViewCredential();
                break;
            }
            return 0;
        }
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
            if (dis->CtlType == ODT_BUTTON) {
                bool disabled = (dis->itemState & ODS_DISABLED) != 0;
                COLORREF bg = ColorForButton((int)dis->CtlID, disabled);
                HBRUSH brush = CreateSolidBrush(bg);
                FillRect(dis->hDC, &dis->rcItem, brush);
                DeleteObject(brush);

                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, RGB(255, 255, 255));
                wchar_t text[64];
                GetWindowTextW(dis->hwndItem, text, 64);
                HGDIOBJ oldFont = SelectObject(dis->hDC, g_hUiFont);
                DrawTextW(dis->hDC, text, -1, &dis->rcItem,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                SelectObject(dis->hDC, oldFont);

                if (dis->itemState & ODS_FOCUS) {
                    DrawFocusRect(dis->hDC, &dis->rcItem);
                }
                return TRUE;
            }
            break;
        }
        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, g_colorText);
            if ((HWND)lParam == g_hStatusStatic) {
                SetBkMode(hdc, OPAQUE);
                SetBkColor(hdc, g_colorBg);
                return (LRESULT)g_hBgBrush;
            }
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)g_hBgBrush;
        }
        case WM_CTLCOLORBTN: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, g_colorText);
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)g_hBgBrush;
        }
        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, g_colorText);
            SetBkColor(hdc, g_colorEditBg);
            return (LRESULT)g_hEditBrush;
        }
        case WM_CTLCOLORLISTBOX: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, g_colorText);
            SetBkColor(hdc, g_colorEditBg);
            return (LRESULT)g_hEditBrush;
        }
        case WM_DESTROY:
            if (g_hBgBrush) DeleteObject(g_hBgBrush);
            if (g_hEditBrush) DeleteObject(g_hEditBrush);
            if (g_hUiFont) DeleteObject(g_hUiFont);
            if (g_hHeadingFont) DeleteObject(g_hHeadingFont);
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    g_vault = new Vault("vault.dat");

    g_hBgBrush = CreateSolidBrush(g_colorBg);
    g_hEditBrush = CreateSolidBrush(g_colorEditBg);

    const wchar_t CLASS_NAME[] = L"PasswordManagerWindow";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = g_hBgBrush;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"Desktop Password Manager",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 300,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) return 0;

    // Best-effort dark title bar (Windows 10 1809+ / Windows 11).
    // Silently does nothing on older systems.
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
    BOOL darkTitleBar = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
        &darkTitleBar, sizeof(darkTitleBar));

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    delete g_vault;
    return 0;
}
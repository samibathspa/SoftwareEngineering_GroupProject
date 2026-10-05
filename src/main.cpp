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

using namespace pm;

namespace {

    Vault* g_vault = nullptr;

    HWND g_hPasswordEdit = nullptr;
    HWND g_hShowPasswordCheck = nullptr;
    HWND g_hLoginBtn = nullptr;
    HWND g_hLogoutBtn = nullptr;
    HWND g_hRecoverBtn = nullptr;
    HWND g_hThemeToggleBtn = nullptr;
    HWND g_hStatusStatic = nullptr;
    HWND g_hListBox = nullptr;

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

    bool g_isDarkMode = true;

    COLORREF g_colorBg = RGB(30, 30, 30);
    COLORREF g_colorEditBg = RGB(45, 45, 48);
    COLORREF g_colorText = RGB(240, 240, 240);

    const COLORREF COLOR_LOGIN = RGB(39, 174, 96);   // green
    const COLORREF COLOR_LOGOUT = RGB(192, 57, 43);   // red
    const COLORREF COLOR_RECOVER = RGB(211, 84, 0);    // orange
    const COLORREF COLOR_TOGGLE = RGB(52, 73, 94);    // neutral blue-grey
    const COLORREF COLOR_DISABLED = RGB(90, 90, 90);

    void SetStatus(const std::wstring& text) {
        SetWindowTextW(g_hStatusStatic, text.c_str());
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

    void RefreshCredentialList() {
        SendMessageW(g_hListBox, LB_RESETCONTENT, 0, 0);
        if (!g_vault->is_unlocked()) return;
        for (const auto& c : g_vault->list()) {
            std::wstring line = L"#" + std::to_wstring(c.id) + L"  " +
                Utf8ToWide(c.service) + L"  (" + Utf8ToWide(c.username) + L")";
            SendMessageW(g_hListBox, LB_ADDSTRING, 0, (LPARAM)line.c_str());
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

    void UpdateButtonStates() {
        bool unlocked = g_vault->is_unlocked();
        EnableWindow(g_hLoginBtn, !unlocked);
        EnableWindow(g_hLogoutBtn, unlocked);
        EnableWindow(g_hPasswordEdit, !unlocked);
        InvalidateRect(g_hLoginBtn, nullptr, TRUE);
        InvalidateRect(g_hLogoutBtn, nullptr, TRUE);
    }

    std::string GetPasswordFieldText() {
        wchar_t buf[256];
        GetWindowTextW(g_hPasswordEdit, buf, 256);
        return WideToUtf8(buf);
    }

    void OnLoginClicked() {
        std::string pw = GetPasswordFieldText();
        if (pw.empty()) {
            MessageBoxW(nullptr, L"Please enter a password.", L"Password Manager",
                MB_OK | MB_ICONWARNING);
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
                    return;
                }
                int confirm = MessageBoxW(nullptr,
                    L"No vault found yet. Create a new one with this master password?",
                    L"Create Vault", MB_YESNO | MB_ICONQUESTION);
                if (confirm != IDYES) return;
                g_vault->create(pw);
                SetStatus(L"Vault created. Logged in.");
            }
            else {
                if (!g_vault->unlock(pw)) {
                    MessageBoxW(nullptr, L"Incorrect master password.", L"Login failed",
                        MB_OK | MB_ICONERROR);
                    return;
                }
                SetStatus(L"Logged in.");
            }
            ClearPasswordField();
            ResetPasswordVisibility();
            UpdateButtonStates();
            RefreshCredentialList();
        }
        catch (const std::exception& e) {
            MessageBoxW(nullptr, Utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }

    void OnLogoutClicked() {
        if (!g_vault->is_unlocked()) return;
        g_vault->lock();
        ClearPasswordField();
        ResetPasswordVisibility();
        RefreshCredentialList();
        UpdateButtonStates();
        SetStatus(L"Logged out.");
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
        std::remove("vault.dat");

        delete g_vault;
        g_vault = new Vault("vault.dat");

        ClearPasswordField();
        ResetPasswordVisibility();
        RefreshCredentialList();
        UpdateButtonStates();
        SetStatus(L"Vault reset. Enter a new master password and click \"Log In\".");
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
            g_colorBg = RGB(30, 30, 30);
            g_colorEditBg = RGB(45, 45, 48);
            g_colorText = RGB(240, 240, 240);
        }
        else {
            g_colorBg = RGB(245, 245, 245);
            g_colorEditBg = RGB(255, 255, 255);
            g_colorText = RGB(20, 20, 20);
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
        case ID_LOGOUT_BTN:       return COLOR_LOGOUT;
        case ID_RECOVER_BTN:      return COLOR_RECOVER;
        case ID_THEME_TOGGLE_BTN: return COLOR_TOGGLE;
        default:                  return RGB(70, 70, 70);
        }
    }

    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"Master password:",
                WS_CHILD | WS_VISIBLE,
                20, 20, 200, 20, hwnd, nullptr, nullptr, nullptr);

            g_hThemeToggleBtn = CreateWindowW(L"BUTTON", L"Light Mode",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                310, 16, 120, 28, hwnd, (HMENU)(intptr_t)ID_THEME_TOGGLE_BTN, nullptr, nullptr);

            g_hPasswordEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_PASSWORD,
                20, 45, 240, 24, hwnd, (HMENU)(intptr_t)ID_PASSWORD_EDIT, nullptr, nullptr);

            g_hShowPasswordCheck = CreateWindowW(L"BUTTON", L"Show password",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 75, 150, 20, hwnd, (HMENU)(intptr_t)ID_SHOW_PASSWORD_CHECK, nullptr, nullptr);

            g_hLoginBtn = CreateWindowW(L"BUTTON", L"Log In",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                20, 105, 100, 32, hwnd, (HMENU)(intptr_t)ID_LOGIN_BTN, nullptr, nullptr);

            g_hLogoutBtn = CreateWindowW(L"BUTTON", L"Log Out",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                130, 105, 100, 32, hwnd, (HMENU)(intptr_t)ID_LOGOUT_BTN, nullptr, nullptr);

            g_hRecoverBtn = CreateWindowW(L"BUTTON", L"Recover Password",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                20, 147, 210, 32, hwnd, (HMENU)(intptr_t)ID_RECOVER_BTN, nullptr, nullptr);

            g_hStatusStatic = CreateWindowW(L"STATIC", L"Not logged in.",
                WS_CHILD | WS_VISIBLE,
                20, 192, 400, 34, hwnd, (HMENU)(intptr_t)ID_STATUS_STATIC, nullptr, nullptr);

            g_hListBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
                20, 230, 400, 160, hwnd, (HMENU)(intptr_t)ID_LISTBOX, nullptr, nullptr);

            UpdateButtonStates();

            if (!g_vault->exists()) {
                SetStatus(L"No vault found. Enter a new master password and click \"Log In\" to create one.");
            }
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
            case ID_LOGIN_BTN:        OnLoginClicked();   break;
            case ID_LOGOUT_BTN:       OnLogoutClicked();  break;
            case ID_RECOVER_BTN:      OnRecoverClicked(); break;
            case ID_THEME_TOGGLE_BTN: ApplyTheme(hwnd, !g_isDarkMode); break;
            case ID_SHOW_PASSWORD_CHECK:
                if (HIWORD(wParam) == BN_CLICKED) OnShowPasswordToggled();
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
                DrawTextW(dis->hDC, text, -1, &dis->rcItem,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE);

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
        CW_USEDEFAULT, CW_USEDEFAULT, 460, 500,
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
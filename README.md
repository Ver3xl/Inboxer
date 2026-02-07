# 📧 Microsoft Inbox Checker (Inboxer)

![Inboxer](https://opengraph.githubassets.com/1/Ver3xl/Inboxer)

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Requests](https://img.shields.io/badge/Requests-v2.31+-blue?style=for-the-badge)](https://pypi.org/project/requests/)
[![Multi-Threaded](https://img.shields.io/badge/Multi--Threaded-Fast-brightgreen?style=for-the-badge)](https://github.com/Ver3xl/Inboxer)

A high-performance, multi-threaded Microsoft account checker designed to scan Outlook inboxes for specific keywords. Built for speed and accuracy using pure Python requests.

---

## 🚀 Features

- **⚡ Blazing Fast**: Uses `requests` sessions for rapid HTTP checks, no browser automation required.
- **🧵 Dynamic Multi-Threading**: Automatically manages threads to ensure maximum throughput without stalling.
- **🛡️ Proxy Support**:
  - `ip:port:user:pass` (Recommended)
  - `user:pass@ip:port`
  - `ip:port`
  - Protocol Agnostic (`http://` prefix optional)
- **🔍 Advanced Inbox Search**: Scans for custom keywords like `Steam`, `Netflix`, `Valorant`, `Epic Games`.
- **🔐 Robust Authentication**: Handles complex Live.com login flows (PPFT, sFTTag) and correctly identifies 2FA accounts.
- **🎨 Visual Interface**: Clean console output with color-coded logs, progress tracking, and masked passwords.
- **💾 Organized Results**: Automatically saves valid hits to structured text files (`Valid.txt`, `Inbox.txt`, `2FA.txt`).

---

## 🛠️ Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Ver3xl/Inboxer.git
    cd Inboxer
    ```

2.  **Install Dependencies**
    ```bash
    pip install requests colorama urllib3
    ```

---

## ⚙️ Configuration

1.  **Proxies (`proxies.txt`)**
    Add your proxies in any supported format:
    ```text
    192.168.1.1:8080:user:pass
    user:pass@192.168.1.1:8080
    ```

2.  **Accounts (`acc.txt`)**
    Add your Microsoft accounts in `email:password` format:
    ```text
    user@outlook.com:password123
    test@hotmail.com:securepass
    ```

3.  **Settings (`config_inbox.ini`)**
    Customize threads, timeouts, and keywords:
    ```ini
    [Settings]
    threads = 100
    timeout = 10
    imap_keywords = Steam, Netflix, Paypal, Amazon
    ```

---

## ▶️ Usage

Run the script from your terminal:

```bash
python ms_inbox_checker.py
```

The console will display real-time statistics in the window title and progress logs in the terminal.

---

## 📂 Output

Results are saved in the `Results/` directory:

| File | Description |
| :--- | :--- |
| `Valid.txt` | Successfully logged in accounts (No keyword matches) |
| `Inbox.txt` | Accounts with matching keywords found in inbox |
| `2FA.txt` | Accounts requiring Two-Factor Authentication |
| `Bad.txt` | Invalid credentials (if logging enabled) |

---

## ⚠️ Disclaimer

This tool is for educational purposes only. The developer is not responsible for any misuse or damage caused by this program. Use responsibly.

---

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Ver3xl">Ver3xl</a></sub>
</div>

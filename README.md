# TeleTunnel v2

A Telegram-based remote access tool for Windows. 
**Disclaimer: For authorized use on systems you own only ! Please 🙇**

## Features
- Remote administration via a Telegram bot.
- Secure control (only accepts commands from your specified Telegram user ID).

The bot have these features:
```ansi
ᴛᴇʟᴇᴛᴜɴɴᴇʟ ᴠ2.0
────────────────────
👤 Identity: USER@HOSTNAME

🛠 ʀᴇᴄᴏɴɴᴀɪssᴀɴᴄᴇ
├── sysinfo  - Full system report
├── ss       - Desktop capture
├── ps       - Process listing
└── ls <path>- Directory browser

⚡️ ᴄᴏᴍᴍᴀɴᴅ ᴄᴇɴᴛᴇʀ
├── > <cmd>  - Native shell
├── spawn <PID> <cmd> - Spoofed exec
├── clip get/set - Clipboard manager
└── kill     - Self-destruct

💾 ғɪʟᴇ ᴏᴘᴇʀᴀᴛɪᴏɴs
├── get <path> - Download from host
├── [Drag/Drop]- Upload to host
└── drops     - List uploads ($1, $LAST)

⌨️ ᴋᴇʏʟᴏɢɢᴇʀ
└── keylog <start|stop|dump|status>

📡 ᴛᴜɴɴᴇʟɪɴɢ
└── open|send|close|streams
────────────────────
```

## Prerequisites
- A Windows environment.
- C++17 compliant compiler (e.g. MinGW).
- The project includes `nlohmann/json.hpp` for JSON parsing. This is included in the repo, removing you some headache searching it

## Setup Instructions

1. **Get a Telegram Bot Token:**
   - Message `@BotFather` on Telegram and create a new bot.
   - Copy the HTTP API Token.

2. **Get Your Telegram Chat ID:**
   - Message `@userinfobot` to get your exact User ID.
   - Alternatively, send a message to your bot and visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates` to find the `id` under `chat`.

3. **Configure the Project:**
   - Open `config.h`.
   - Replace `"YOUR BOT TOKEN HERE"` with your actual bot token.
   - Replace `"XXXXXXXXXX"` with your personal Telegram User ID.

## Compilation

Ensure you have required Windows libraries: `wininet`, `ws2_32`, `gdiplus`, `ole32`, and `iphlpapi`.

**using GCC/MinGW:**
```bash
g++ -std=c++17 -O2 -mwindows -I. -Inlohmann "./TeleTunnel v2.cpp" -o TeleTunnelv2.exe -lwininet -lws2_32 -lgdiplus -lole32 -liphlpapi -static -static-libgcc -static-libstdc++
```
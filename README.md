# Kiroshi: an Anti-Cheat Artifacts Detector

An **IDA Pro plugin** that statically detects **Anti-Cheat Artifacts** in Windows binaries.  
meant to help reverse engineers and security researchers quickly identify the presence of
commercial or custom anti-cheat mechanisms during analysis.

> ⚠️ This plugin is for **reverse engineering and academic research only**.

---

<img width="1919" height="1039" alt="Screenshot 2026-01-02 023528" src="https://github.com/user-attachments/assets/5ea87c90-dfee-4d17-8985-39e71cda0541" />

## ✨ Features

- 🔍 **Static detection of Anti-Cheat Artifacts**
  - Known Anti-Cheat strings (EAC, BattlEye, Vanguard, FACEIT, XIGNCODE, etc.)
  - Suspicious Windows APIs commonly used by Anti-Cheats
  - Anti-debugging and Anti-VM related imports
- 🧠 **Function-level scanning**
- 📊 **Interactive results view**
  - Clickable results that jump directly to the artifact in IDA
- 🧩 **Extensible rule-based design**
  - Easy to add new signatures and heuristics
- ⚡ Built on the **IDA SDK (C++)**

---

## 🛠️ Detection Logic (Overview)

The plugin analyzes the binary for common Anti-Cheat techniques, including:

### 1. Known Anti-Cheat Strings
Examples:
- `EasyAntiCheat`
- `BEService`
- `vgk.sys`
- `FACEIT AC`
- `XIGNCODE`

### 2. Suspicious Imports / APIs
Examples:
- `NtQueryInformationProcess`
- `ZwQuerySystemInformation`
- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `OutputDebugString`
- `NtSetInformationThread`

### 3. Heuristic Indicators
- Unusual driver-related strings
- Anti-debug patterns
- Process / thread inspection behavior

> This is **static analysis only**, no runtime hooking or bypassing is done.

---

## 📦 Installation

You can download the pre-built plugin from the [releases](https://github.com/not1cyyy/Anti-Cheat-Artifacts-Detector/releases) page. 
Just place the plugin in the IDA Pro plugins directory.

## 📦 Building from Source

### Requirements
- IDA Pro 9.0
- IDA SDK
- Windows SDK (10.0.26100.0)
- Visual Studio (MSVC)

### Build Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/not1cyyy/Anti-Cheat-Artifacts-Detector.git
   cd Anti-Cheat-Artifacts-Detector
   ```
2. Build the plugin:
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```
## 🚀 Usage

1. Open IDA Pro and load the binary you want to analyze.
2. Go to the "Plugins" menu and select "Anti-Cheat Artifacts Detector".
3. Choose if you want to scan the current function or all functions.
4. The plugin will scan the binary and display the results in a chooser window.
5. You can then double click on the results to jump to the artifact in IDA.

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## 📝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## ⭐ Acknowledgements

- [IDA SDK](https://github.com/HexRaysSA/ida-sdk)
- [IDA Pro](https://www.hex-rays.com/products/ida/)
- Reverse engineering & game security research community

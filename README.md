# 🛡️ AI Binary Security Scanner & Auditor

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Qt 6](https://img.shields.io/badge/Qt-6.x-green.svg)](https://www.qt.io/)
[![Ghidra](https://img.shields.io/badge/Decompiler-Ghidra-orange.svg)](https://ghidra-sre.org/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

#Important!!!
 you must run this in order to run the setup:
 '''
cd "C:\Path\To\Your\AI_Sec"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
.\setup_environment.ps1
'''
An advanced, multi-stage binary security scanner and reverse-engineering auditor built with **C++ (Qt 6)**, **Ghidra Headless**, **Python**, and **Claude AI models**.

The application offers two distinct scanning pipelines depending on speed and depth requirements:
* **⚡ Fast AI Scan Mode:** Performs rapid, real-time feature extraction on raw binary headers, byte vectors, and PE structures using **Claude 3.5 Haiku**—no decompilation required.
* **🔬 Deep AI Audit Mode:** Executes headless decompilation via **Ghidra**, extracts candidate functions, screens them using **Claude 3.5 Haiku**, and performs deep vulnerability auditing on flagged code using **Claude 3 Opus**.

If a malicious binary or critical vulnerability is identified, the app features automated threat remediation, prompting for standard deletion or **Windows UAC Administrator elevation** to force-remove protected threats.

---

## 📁 Repository Layout

```text
.
├── CMakeLists.txt              # CMake build definitions
├── main.cpp                    # Qt Application entry point
├── mainwindow.h                # Qt MainWindow & ScanWorker header
├── mainwindow.cpp              # UI logic, network routines, and process worker
├── decompile.py                # Python wrapper for Ghidra Headless extraction
├── setup_environment.ps1       # One-click Windows setup automation script
├── python.exe                  # Portable Python executable (optional bundle)
├── jdk-21_windows-x64_bin/     # Portable JDK 21 folder (optional bundle)
└── ghidra/                     # Ghidra deployment directory
    ├── ghidra_extract.py       # Ghidra Python decompiler script
    └── support/
        └── analyzeHeadless.bat # Ghidra headless executable launcher

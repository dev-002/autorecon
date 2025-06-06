# 🛡️ Automated Recon (Using Nmap and Nuclei)

An automated reconnaissance tool for penetration testers and bug bounty hunters. This Python script scans a target using Nmap and feeds the results into Nuclei to detect known vulnerabilities based on exposed services.

---

## 🔍 Description

Manual service detection and enumeration can be repetitive and time-consuming. This tool streamlines the process by:

- Performing a full Nmap scan on the target IP or domain.
- Parsing and identifying open ports and running services.
- Automatically feeding this data into Nuclei for vulnerability scanning.
- Saving results in structured formats for reporting or further analysis.

Perfect for internal pentests, red teaming, or initial bug bounty recon phases.

---

## ⚙️ Features

- 🔄 End-to-end automated workflow (Nmap ➝ Nuclei)
- 🧠 Intelligent service extraction from Nmap output
- 📦 Generates organized scan results (`nmap.xml`, `nuclei.json`)
- 🖥️ Terminal output + file-based logging
- 💡 Modular and extendable Python script

---

## 🛠️ Usage

```bash
python3 autorecon.py <target>
```

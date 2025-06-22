# CYBERDUDEBIVASH-AI-SCANNER

**CYBERDUDEBIVASH-AI-SCANNER** is an advanced AI-powered security scanner for Windows and Linux filesystems, designed for the **Cyber Security Conference 101**. It detects malware, vulnerabilities, and suspicious activities using AI-driven anomaly detection, YARA rules, and system monitoring, tailored for cybersecurity professionals combating 2025’s AI and Web3 threats.

## Features

- **File Scanning**: Scans files for known malware using hash matching, YARA rules, and AI-based anomaly detection.
- **Process Monitoring**: Identifies suspicious processes based on CPU usage and naming patterns.
- **Network Analysis**: Detects anomalous network connections to malicious IPs or ports.
- **Vulnerability Checks**: Identifies outdated OS versions and misconfigurations (e.g., world-writable files on Linux).
- **Cross-Platform**: Runs on Windows and Linux with a unified CLI interface.
- **Reporting**: Generates detailed JSON reports for scan results.

## Tech Stack

- **Python 3.8+**: Cross-platform scripting language.
- **YARA**: Malware pattern matching library.
- **psutil**: System monitoring for processes and network connections.
- **hashlib**: File hash calculation for known malware detection.
- **logging**: Comprehensive scan logging.
- **argparse**: CLI argument parsing.

## Prerequisites

- Python 3.8 or higher installed on Windows or Linux.
- Administrative privileges for process and network monitoring.
- Required Python packages:
  ```bash
  pip install yara-python psutil
  ```
- Optional: YARA rules file (e.g., from [YARA Rules GitHub](https://github.com/Yara-Rules/rules)).

## Installation

1. **Clone or Download**:
   - Clone the repository: `git clone [repository-url]` or download `cyberdudebivash_ai_scanner.py`.
   - Alternatively, use the provided code from conference materials.

2. **Install Dependencies**:
   ```bash
   pip install yara-python psutil
   ```

3. **Prepare YARA Rules** (Optional):
   - Download or create a YARA rules file (e.g., `rules.yar`).
   - Place it in the same directory as the scanner or specify its path during execution.

4. **Run the Scanner**:
   - Ensure Python is in your system PATH.
   - Execute with or without arguments (see Usage).

## Usage

Run the scanner via the command line with optional arguments for directory scanning, YARA rules, and report output.

```bash
python cyberdudebivash_ai_scanner.py --directory /path/to/scan --yara-rules rules.yar --report scan_report.json
```

### Arguments
- `--directory, -d`: Path to the directory to scan (e.g., `/home/user` or `C:\Users\user`).
- `--yara-rules, -y`: Path to YARA rules file for malware detection.
- `--report, -r`: Path to save the JSON report (default: `scan_report.json`).

### Examples
- Scan a directory with default settings:
  ```bash
  python cyberdudebivash_ai_scanner.py -d /home/user/documents
  ```
- Scan with YARA rules and custom report:
  ```bash
  python cyberdudebivash_ai_scanner.py -d C:\Users\user\docs -y rules.yar -r results.json
  ```
- Run system-wide checks without directory scanning:
  ```bash
  python cyberdudebivash_ai_scanner.py
  ```

### Demo Mode
- Use a test directory with files named `malware-test.txt` or `testvirus.exe` to trigger AI anomaly detection.
- Create a mock YARA rule (e.g., detecting EICAR test strings) for conference demos.
- Sample YARA rule (`eicar.yar`):
  ```yara
  rule EICAR_Test {
      strings:
          $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
      condition:
          $eicar
  }
  ```

## Output

- **Log File**: `cyberdudebivash_ai_scanner.log` contains detailed scan logs.
- **Report File**: JSON report (e.g., `scan_report.json`) includes:
  - Timestamp
  - Files scanned
  - Malware detections (hash, YARA, AI anomalies)
  - Suspicious processes
  - Network anomalies
  - System vulnerabilities

Sample report snippet:
```json
{
  "timestamp": "2025-06-22T13:18:00",
  "files_scanned": 100,
  "malware_detected": [
    {
      "file": "/home/user/malware-test.txt",
      "type": "AI Anomaly",
      "details": "Suspicious filename pattern"
    }
  ],
  "processes_suspicious": [],
  "network_anomalies": [],
  "vulnerabilities": [
    {
      "type": "Outdated OS",
      "details": "Ubuntu 16.04 detected; unsupported and vulnerable"
    }
  ]
}
```

## Demo Notes for Cyber Security Conference 101

- **Purpose**: Demonstrate AI-driven security scanning for filesystems, addressing 2025’s malware trends (67% rise in AI-driven attacks).
- **Key Features**:
  - AI anomaly detection for unknown threats.
  - YARA integration for known malware signatures.
  - Cross-platform support for diverse environments.
- **Engagement**: Run a live demo scanning a test directory with mock malware files and outdated OS settings.
- **Handout**: Share this README and a QR code linking to the GitHub repo: [Insert Repo Link].

## Development Notes

- **AI Model**: Uses mock AI logic for anomaly detection. For production, integrate a trained ML model (e.g., scikit-learn, TensorFlow) with features like file entropy, n-gram analysis, or behavioral patterns.
- **YARA Rules**: Mock implementation supports custom rules. Expand with community rulesets for comprehensive coverage.
- **Extensibility**:
  - Add CVE database integration (e.g., NVD API) for vulnerability scanning.[](https://geekflare.com/cybersecurity/linux-security-scanner/)
  - Incorporate network packet analysis with Scapy or Wireshark libraries.
  - Enable real-time alerts via email or SIEM integration (e.g., Splunk).
- **Security**: Runs with minimal permissions; requires admin access for process/network monitoring.
- **Inspiration**: Aligns with tools like ClamAV and Vuls for Linux scanning, with AI enhancements.[](https://geekflare.com/cybersecurity/linux-security-scanner/)

## Limitations

- **Mock AI**: Demo uses heuristic-based anomaly detection; production requires a trained ML model.
- **YARA Dependency**: Requires external rules for advanced malware detection.
- **Performance**: Directory scanning may be slow for large filesystems; optimize with multiprocessing.
- **Network Analysis**: Limited to active connections; expand with packet capture for deeper insights.
- **Vulnerability Checks**: Basic OS and file permission checks; integrate with OpenVAS for comprehensive scans.[](https://www.breachlock.com/resources/blog/top-5-open-source-tools-for-network-vulnerability-scanning/)

## Contributing

- Fork the repository and submit pull requests for new features (e.g., CVE lookup, GUI interface).
- Report issues or suggest improvements via [Insert GitHub Issues Link].
- Contact: [Insert Email, e.g., support@cyberdudebivash.com].

## Resources

- **Documentation**:
  - [YARA](https://yara.readthedocs.io)
  - [psutil](https://psutil.readthedocs.io)
  - [Python](https://docs.python.org/3/)
- **Related Tools**:
  - ClamAV: Open-source antivirus for Linux.[](https://geekflare.com/cybersecurity/linux-security-scanner/)
  - Vuls: Vulnerability scanner for Linux/FreeBSD.[](https://geekflare.com/cybersecurity/linux-security-scanner/)
  - OpenVAS: Comprehensive vulnerability scanner.[](https://www.breachlock.com/resources/blog/top-5-open-source-tools-for-network-vulnerability-scanning/)
- **Conference Context**: Explore AI and Web3 cybersecurity at Cyber Security Conference 101: [Insert Event Link].

## License

MIT License. Free to use, modify, and distribute with attribution to CYBERDUDEBIVASH.

## Acknowledgments

- Built for **Cyber Security Conference 101** to address 2025’s AI-driven threat landscape.
- Powered by **xAI** and inspired by open-source tools like ClamAV, Vuls, and YARA.
- Thanks to conference attendees for their feedback and engagement.

**Scan smart, stay secure!** 🚀  
#CyberSecurity101 #AIScanner #MalwareDetection
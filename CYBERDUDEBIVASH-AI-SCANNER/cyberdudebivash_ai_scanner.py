import os
import sys
import time
import hashlib
import platform
import psutil
import yara
import logging
import argparse
from datetime import datetime
import socket
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyberdudebivash_ai_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberDudeBivashAIScanner:
    def __init__(self, yara_rules_path=None):
        self.platform = platform.system().lower()
        self.yara_rules = self.load_yara_rules(yara_rules_path) if yara_rules_path else None
        self.known_malware_hashes = {
            'eicar_test': '44d88612fea8a8f36de82e1278abb02f',  # EICAR test file MD5
        }
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'files_scanned': 0,
            'malware_detected': [],
            'processes_suspicious': [],
            'network_anomalies': [],
            'vulnerabilities': []
        }
        logger.info(f"Initialized CYBERDUDEBIVASH-AI-SCANNER on {self.platform}")

    def load_yara_rules(self, rules_path):
        """Load YARA rules for malware detection."""
        try:
            rules = yara.compile(filepath=rules_path)
            logger.info(f"Loaded YARA rules from {rules_path}")
            return rules
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None

    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None

    def ai_anomaly_detection(self, file_path):
        """Mock AI-based anomaly detection (simulates ML model)."""
        # Mock logic: Flag files with unusual extensions or specific keywords
        suspicious_extensions = ['.scr', '.pif', '.bat', '.cmd']
        file_name = os.path.basename(file_path).lower()
        if any(file_name.endswith(ext) for ext in suspicious_extensions):
            return {'is_suspicious': True, 'reason': f'Suspicious extension {file_name}'}
        if 'malware' in file_name or 'testvirus' in file_name:
            return {'is_suspicious': True, 'reason': 'Suspicious filename pattern'}
        return {'is_suspicious': False, 'reason': 'No anomalies detected'}

    def scan_file(self, file_path):
        """Scan a single file for malware and vulnerabilities."""
        self.scan_results['files_scanned'] += 1
        logger.debug(f"Scanning file: {file_path}")

        # Hash-based detection
        file_hash = self.calculate_file_hash(file_path)
        if file_hash in self.known_malware_hashes.values():
            detection = {
                'file': file_path,
                'type': 'Known Malware',
                'details': f"Hash match: {file_hash}"
            }
            self.scan_results['malware_detected'].append(detection)
            logger.warning(f"Malware detected: {detection}")
            return

        # YARA rule-based detection
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                if matches:
                    detection = {
                        'file': file_path,
                        'type': 'YARA Match',
                        'details': f"YARA rules matched: {', '.join([m.rule for m in matches])}"
                    }
                    self.scan_results['malware_detected'].append(detection)
                    logger.warning(f"Malware detected: {detection}")
                    return
            except Exception as e:
                logger.error(f"YARA scan failed for {file_path}: {e}")

        # AI-based anomaly detection
        ai_result = self.ai_anomaly_detection(file_path)
        if ai_result['is_suspicious']:
            detection = {
                'file': file_path,
                'type': 'AI Anomaly',
                'details': ai_result['reason']
            }
            self.scan_results['malware_detected'].append(detection)
            logger.warning(f"AI anomaly detected: {detection}")

    def scan_directory(self, dir_path):
        """Recursively scan a directory for files."""
        try:
            dir_path = Path(dir_path).resolve()
            for root, _, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        self.scan_file(file_path)
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error scanning directory {dir_path}: {e}")

    def monitor_processes(self):
        """Monitor running processes for suspicious activity."""
        logger.info("Monitoring running processes...")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
                # Mock AI logic: Flag processes with high CPU or unusual names
                if proc_info['name'].lower() in ['malware.exe', 'testvirus']:
                    detection = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'details': 'Suspicious process name'
                    }
                    self.scan_results['processes_suspicious'].append(detection)
                    logger.warning(f"Suspicious process: {detection}")
                elif proc.cpu_percent(interval=0.1) > 90:
                    detection = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'details': 'High CPU usage anomaly'
                    }
                    self.scan_results['processes_suspicious'].append(detection)
                    logger.warning(f"Suspicious process: {detection}")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug(f"Process access error: {e}")

    def analyze_network(self):
        """Analyze network connections for anomalies."""
        logger.info("Analyzing network connections...")
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Mock AI logic: Flag connections to known malicious IPs or high port activity
                    malicious_ips = ['192.168.1.100', '10.0.0.99']
                    if conn.raddr.ip in malicious_ips:
                        detection = {
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'details': 'Connection to known malicious IP'
                        }
                        self.scan_results['network_anomalies'].append(detection)
                        logger.warning(f"Network anomaly: {detection}")
                    elif conn.raddr.port in [4444, 6667]:  # Common malware ports
                        detection = {
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'details': 'Suspicious port activity'
                        }
                        self.scan_results['network_anomalies'].append(detection)
                        logger.warning(f"Network anomaly: {detection}")
        except Exception as e:
            logger.error(f"Network analysis error: {e}")

    def check_vulnerabilities(self):
        """Check system for known vulnerabilities."""
        logger.info("Checking system vulnerabilities...")
        # Mock vulnerability check: Verify OS version and common misconfigurations
        os_version = platform.version()
        if self.platform == 'windows' and '6.1' in os_version:
            vuln = {
                'type': 'Outdated OS',
                'details': 'Windows 7 detected; unsupported and vulnerable'
            }
            self.scan_results['vulnerabilities'].append(vuln)
            logger.warning(f"Vulnerability: {vuln}")
        elif self.platform == 'linux' and 'Ubuntu 16.04' in platform.release():
            vuln = {
                'type': 'Outdated OS',
                'details': 'Ubuntu 16.04 detected; unsupported and vulnerable'
            }
            self.scan_results['vulnerabilities'].append(vuln)
            logger.warning(f"Vulnerability: {vuln}")

        # Check for world-writable files on Linux
        if self.platform == 'linux':
            try:
                for root, _, files in os.walk('/etc'):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.stat(file_path).st_mode & 0o022:
                            vuln = {
                                'type': 'Misconfiguration',
                                'details': f"World-writable file detected: {file_path}"
                            }
                            self.scan_results['vulnerabilities'].append(vuln)
                            logger.warning(f"Vulnerability: {vuln}")
            except Exception as e:
                logger.error(f"Vulnerability check error: {e}")

    def save_report(self, output_path):
        """Save scan results to a JSON report."""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.scan_results, f, indent=4)
            logger.info(f"Report saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

    def run(self, dir_path=None, report_path='scan_report.json'):
        """Execute full scan workflow."""
        logger.info("Starting CYBERDUDEBIVASH-AI-SCANNER...")
        start_time = time.time()

        if dir_path:
            self.scan_directory(dir_path)
        self.monitor_processes()
        self.analyze_network()
        self.check_vulnerabilities()
        self.save_report(report_path)

        elapsed_time = time.time() - start_time
        logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        logger.info(f"Files scanned: {self.scan_results['files_scanned']}")
        logger.info(f"Malware detected: {len(self.scan_results['malware_detected'])}")
        logger.info(f"Suspicious processes: {len(self.scan_results['processes_suspicious'])}")
        logger.info(f"Network anomalies: {len(self.scan_results['network_anomalies'])}")
        logger.info(f"Vulnerabilities: {len(self.scan_results['vulnerabilities'])}")

def main():
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH-AI-SCANNER: Advanced AI Security Scanner for Windows and Linux"
    )
    parser.add_argument(
        '--directory', '-d',
        type=str,
        help='Directory path to scan for files'
    )
    parser.add_argument(
        '--yara-rules', '-y',
        type=str,
        help='Path to YARA rules file for malware detection'
    )
    parser.add_argument(
        '--report', '-r',
        type=str,
        default='scan_report.json',
        help='Path to save the scan report (default: scan_report.json)'
    )
    args = parser.parse_args()

    scanner = CyberDudeBivashAIScanner(yara_rules_path=args.yara_rules)
    scanner.run(dir_path=args.directory, report_path=args.report)

if __name__ == '__main__':
    main()
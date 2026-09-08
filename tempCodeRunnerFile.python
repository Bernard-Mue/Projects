import hashlib
import re
import os
import json
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

class SecurityToolkit:
    def __init__(self):
        self.log_patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
            'timestamp': r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
            'error_code': r'Error:\s*\d{3}',
            'file_path': r'[A-Za-z]:\\(?:[^\\:\n"<>|]+\\)*[^\\:\n"<>|]+\.\w+'
        }
    
    # ============ LOG ANALYSIS ============
    
    def analyze_log_file(self, log_path: str) -> Dict:
        """
        Comprehensive log analyzer with statistical insights.
        """
        if not os.path.exists(log_path):
            return {"error": "Log file not found"}
        
        results = {
            "filename": os.path.basename(log_path),
            "file_size": os.path.getsize(log_path),
            "lines_analyzed": 0,
            "unique_ips": {},
            "unique_users": set(),
            "error_counts": Counter(),
            "timestamp_distribution": [],
            "suspicious_activities": [],
            "summary": {}
        }
        
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                results["lines_analyzed"] += 1
                line = line.strip()
                
                # Extract IPs
                ips = re.findall(self.log_patterns['ip'], line)
                for ip in ips:
                    results["unique_ips"][ip] = results["unique_ips"].get(ip, 0) + 1
                
                # Extract emails
                emails = re.findall(self.log_patterns['email'], line)
                results["unique_users"].update(emails)
                
                # Extract errors
                errors = re.findall(self.log_patterns['error_code'], line)
                results["error_counts"].update(errors)
                
                # Extract timestamps
                timestamps = re.findall(self.log_patterns['timestamp'], line)
                results["timestamp_distribution"].extend(timestamps)
                
                # Detect suspicious activities
                suspicious = self._detect_suspicious_logs(line)
                if suspicious:
                    results["suspicious_activities"].append({
                        "line_number": line_num,
                        "content": line,
                        "reason": suspicious
                    })
        
        # Generate summary
        results["summary"] = {
            "total_errors": sum(results["error_counts"].values()),
            "unique_ips_count": len(results["unique_ips"]),
            "most_active_ip": max(results["unique_ips"].items(), key=lambda x: x[1])[0] if results["unique_ips"] else "None",
            "top_errors": results["error_counts"].most_common(3)
        }
        
        return results
    
    def _detect_suspicious_logs(self, line: str) -> Optional[str]:
        """Identify suspicious log patterns."""
        suspicious_patterns = {
            r'failed (login|password|authentication)': 'Failed login attempt',
            r'sql.*inject': 'Potential SQL injection',
            r'(\'|\"|\%27|\%22).*(or|and).*(\=|\>|\<)': 'SQL injection pattern',
            r'\.\./|\.\.\\': 'Directory traversal attempt',
            r'\$\{.*\}': 'Potential code injection',
            r'<script|javascript:': 'XSS attempt',
            r'admin|root|administrator.*(password|pass|pwd)': 'Sensitive credential exposure'
        }
        
        line_lower = line.lower()
        for pattern, reason in suspicious_patterns.items():
            if re.search(pattern, line_lower, re.IGNORECASE):
                return reason
        return None
    
    # ============ FILE HASHING TOOL ============
    
    def compute_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Dict:
        """
        Calculate file hash and gather metadata.
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        result = {
            "filename": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
            "algorithm": algorithm,
            "hash": ""
        }
        
        try:
            hash_func = getattr(hashlib, algorithm)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            result["hash"] = hash_func.hexdigest()
            return result
        except AttributeError:
            return {"error": f"Unsupported algorithm: {algorithm}"}
    
    def batch_hash_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Hash all files in a directory with optional extension filter.
        """
        if not os.path.isdir(directory):
            return [{"error": "Directory not found"}]
        
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Filter by extension if specified
                if extensions:
                    if not any(file.endswith(ext) for ext in extensions):
                        continue
                
                # Hash the file
                hash_result = self.compute_file_hash(file_path)
                if "error" not in hash_result:
                    results.append(hash_result)
        
        return results
    
    # ============ INTEGRATED TOOL ============
    
    def generate_security_report(self, log_path: str, directory_to_hash: str) -> Dict:
        """
        Generate a comprehensive security report combining log analysis and file hashing.
        """
        report = {
            "generated_at": datetime.now().isoformat(),
            "log_analysis": self.analyze_log_file(log_path),
            "file_integrity": self.batch_hash_directory(directory_to_hash),
            "recommendations": []
        }
        
        # Generate recommendations based on findings
        # Log analysis recommendations
        if report["log_analysis"].get("summary", {}).get("total_errors", 0) > 100:
            report["recommendations"].append("High error rate detected. Investigate root cause.")
        
        if report["log_analysis"].get("suspicious_activities"):
            report["recommendations"].append(f"Found {len(report['log_analysis']['suspicious_activities'])} suspicious activities. Review immediately.")
        
        # File integrity recommendations
        if report["file_integrity"]:
            report["recommendations"].append("Created baseline hashes for files. Store securely for future comparisons.")
        
        return report

# ============ COMMAND-LINE INTERFACE ============

def main():
    """Example usage of the SecurityToolkit."""
    toolkit = SecurityToolkit()
    
    print("=== Security Toolkit ===")
    print("1. Analyze a log file")
    print("2. Hash a single file")
    print("3. Hash all files in a directory")
    print("4. Generate full security report")
    
    choice = input("Select option (1-4): ")
    
    if choice == '1':
        log_path = input("Enter log file path: ")
        results = toolkit.analyze_log_file(log_path)
        print(json.dumps(results, indent=2, default=str))
    
    elif choice == '2':
        file_path = input("Enter file path: ")
        algorithm = input("Enter hash algorithm (sha256, md5, sha1): ") or 'sha256'
        result = toolkit.compute_file_hash(file_path, algorithm)
        print(json.dumps(result, indent=2))
    
    elif choice == '3':
        directory = input("Enter directory path: ")
        extensions_input = input("Enter extensions to filter (comma-separated, e.g., .exe,.dll): ")
        extensions = [ext.strip() for ext in extensions_input.split(',')] if extensions_input else None
        results = toolkit.batch_hash_directory(directory, extensions)
        print(json.dumps(results, indent=2))
    
    elif choice == '4':
        log_path = input("Enter log file path: ")
        directory = input("Enter directory to hash: ")
        report = toolkit.generate_security_report(log_path, directory)
        print(json.dumps(report, indent=2, default=str))
    
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
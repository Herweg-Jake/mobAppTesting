import os
import re
import argparse
import xml.etree.ElementTree as ET
import json

class SecurityAnalyzer:
    def __init__(self, decompiled_dir):
        self.decompiled_dir = decompiled_dir
        self.manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
        self.java_dir = os.path.join(decompiled_dir, "sources")
        self.issues = []
    
    def analyze(self):
        print(f"Analyzing decompiled code in {self.decompiled_dir}...")
        
        self.check_exported_components()
        self.check_webview_security()
        self.check_insecure_connections()
        self.check_hardcoded_secrets()
        self.check_insecure_random()
        self.check_logging()
        
        return self.issues
    
    def check_exported_components(self):
        if not os.path.exists(self.manifest_path):
            print("Warning: AndroidManifest.xml not found")
            return
        
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            
            ns = {"android": "http://schemas.android.com/apk/res/android"}
            
            exported_activities = []
            for activity in root.findall(".//activity", ns):
                exported = activity.get("{http://schemas.android.com/apk/res/android}exported")
                name = activity.get("{http://schemas.android.com/apk/res/android}name")
                
                if exported == "true":
                    exported_activities.append(name)
                    self.issues.append({
                        "type": "Exported Activity",
                        "severity": "HIGH",
                        "description": f"Activity {name} is exported and might be accessible by other apps",
                        "location": "AndroidManifest.xml"
                    })
                    
            print(f"Found {len(exported_activities)} exported activities")
            
        except Exception as e:
            print(f"Error analyzing manifest: {e}")
    
    def check_webview_security(self):
        js_enabled_pattern = re.compile(r'\.setJavaScriptEnabled\s*\(\s*true\s*\)')
        
        for root, _, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # check for js enabled
                            if js_enabled_pattern.search(content):
                                self.issues.append({
                                    "type": "Insecure WebView",
                                    "severity": "MEDIUM",
                                    "description": "JavaScript is enabled in WebView which can lead to XSS attacks",
                                    "location": file_path
                                })
                    except:
                        continue
    
    def check_insecure_connections(self):
        if not os.path.exists(self.manifest_path):
            return
            
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            
            # check cleartext traffic
            cleartext_allowed = root.find(".//application[@android:usesCleartextTraffic='true']", 
                                      {"android": "http://schemas.android.com/apk/res/android"})
            
            if cleartext_allowed is not None:
                self.issues.append({
                    "type": "Insecure Network",
                    "severity": "HIGH",
                    "description": "App allows cleartext traffic which can be intercepted",
                    "location": "AndroidManifest.xml"
                })
                
            # look for network security config
            config_file = os.path.join(self.decompiled_dir, "resources", "res", "xml", "network_security_config.xml")
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if "cleartextTrafficPermitted=\"true\"" in content:
                        self.issues.append({
                            "type": "Insecure Network Config",
                            "severity": "HIGH",
                            "description": "Cleartext traffic is permitted in the network security config",
                            "location": config_file
                        })
        except:
            pass
    
    def check_hardcoded_secrets(self):
        secret_patterns = [
            (r'(?i)api[_-]?key\s*=\s*["\']([^"\']{10,})["\']', "API Key"),
            (r'(?i)password\s*=\s*["\']([^"\']{3,})["\']', "Password"),
            (r'(?i)secret\s*=\s*["\']([^"\']{5,})["\']', "Secret"),
            (r'(?i)firebase.*\.com', "Firebase URL"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
        ]
        
        for root, _, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            for pattern, secret_type in secret_patterns:
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    self.issues.append({
                                        "type": "Hardcoded Secret",
                                        "severity": "HIGH",
                                        "description": f"Potential {secret_type} found in source code",
                                        "location": file_path
                                    })
                    except:
                        continue
    
    def check_insecure_random(self):
        insecure_random_patterns = [
            r'java\.util\.Random',
            r'Math\.random\(\)'
        ]
        
        for root, _, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            for pattern in insecure_random_patterns:
                                if re.search(pattern, content):
                                    self.issues.append({
                                        "type": "Insecure Random",
                                        "severity": "MEDIUM",
                                        "description": "Insecure random number generator used",
                                        "location": file_path
                                    })
                    except:
                        continue
    
    def check_logging(self):
        log_patterns = [
            r'Log\.(v|d|i|w|e)\([^)]*((password|token|key|secret|credential)[^)]*)\)',
        ]
        
        for root, _, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            for pattern in log_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.issues.append({
                                        "type": "Sensitive Logging",
                                        "severity": "MEDIUM",
                                        "description": "Potentially sensitive information being logged",
                                        "location": file_path
                                    })
                    except:
                        continue

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for security issues")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    analyzer = SecurityAnalyzer(args.decompiled_dir)
    issues = analyzer.analyze()
    
    #print summary
    print(f"\nAnalysis complete! Found {len(issues)} potential security issues.")
    
    if issues:
        issues_by_severity = {}
        for issue in issues:
            severity = issue["severity"]
            if severity not in issues_by_severity:
                issues_by_severity[severity] = 0
            issues_by_severity[severity] += 1
            
        for severity, count in issues_by_severity.items():
            print(f"- {severity}: {count} issues")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()

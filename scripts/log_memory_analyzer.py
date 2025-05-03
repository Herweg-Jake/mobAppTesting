import os
import re
import argparse
import json

def analyze_log_leakage(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # logging of sensitive information
    sensitive_log_patterns = [
        (r'Log\.(v|d|i|w|e)\([^)]*?(?:password|token|key|secret|cred|auth|user|email)[^)]*?\)', 
         "Sensitive data may be logged"),
        (r'System\.out\.print(ln)?\([^)]*?(?:password|token|key|secret|cred|auth|user|email)[^)]*?\)',
         "System.out printing sensitive data"),
        (r'\.debug\([^)]*?(?:password|token|key|secret|cred|auth|user|email)[^)]*?\)',
         "Debug logging of sensitive data"),
    ]
    
    # possible log leakage issues
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # skip library code
                        if "com/google/" in file_path or "androidx/" in file_path:
                            continue
                            
                        for pattern, description in sensitive_log_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Log Leakage",
                                    "severity": "HIGH",
                                    "description": description,
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def analyze_memory_leakage(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # possible memory leakage risks
    memory_patterns = [
        (r'\.getText\(\).toString\(\)', 
         "EditText content stored as String which may remain in memory"),
        (r'String\s+\w+\s*=\s*.*?(password|token|key|secret|cred)[^;]*;',
         "Sensitive data stored in String variable instead of char array"),
        (r'FLAG_SECURE.*?false',
         "Screen security flag disabled, allowing screenshots"),
        (r'\.putString\([^,]*?(password|token|key|secret|cred)[^,]*?,',
         "Storing sensitive data in SharedPreferences as plain string")
    ]
    
    # memory leakage issues
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                # skip library code
                if "com/google/" in file_path or "androidx/" in file_path:
                    continue
                    
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for pattern, description in memory_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Memory Leakage",
                                    "severity": "MEDIUM",
                                    "description": description,
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for log and memory leakage")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    log_issues = analyze_log_leakage(args.decompiled_dir)
    memory_issues = analyze_memory_leakage(args.decompiled_dir)
    
    all_issues = log_issues + memory_issues
    
    # print summary
    print(f"\nAnalysis complete! Found {len(all_issues)} potential log/memory leakage issues:")
    print(f"- Log Leakage: {len(log_issues)} issues")
    print(f"- Memory Leakage: {len(memory_issues)} issues")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
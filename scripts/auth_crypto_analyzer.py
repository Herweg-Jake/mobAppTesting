import os
import re
import argparse
import json

def analyze_authentication(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # authentication issues
    auth_patterns = [
        (r'(username|user|login)\s*=\s*["\']([^"\']+)["\']', 
         "Hardcoded username found"),
        (r'password\s*=\s*["\']([^"\']+)["\']',
         "Hardcoded password found"),
        (r'SHA-?1|MD5', 
         "Weak hash algorithm used for passwords"),
        (r'\.equals\(.*?password', 
         "Potential timing attack vulnerability in password comparison"),
        (r'getSharedPreferences\([^)]*\)\.getString\([^)]*password[^)]*\)',
         "Reading password from SharedPreferences without encryption")
    ]
    
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
                        
                        for pattern, description in auth_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Authentication Issue",
                                    "severity": "HIGH",
                                    "description": description,
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def analyze_cryptography(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # cryptography issues
    crypto_patterns = [
        (r'DES|3DES|RC2|RC4|BLOWFISH|MD4|MD5|SHA-?1', 
         "Weak or deprecated cryptographic algorithm"),
        (r'ECB|Electronic\s+Codebook', 
         "Insecure ECB mode used for encryption"),
        (r'new\s+SecretKeySpec\([^,]+,.+\)', 
         "Check for hardcoded encryption key"),
        (r'Cipher\.getInstance\([^)]*\)', 
         "Cipher implementation - check for proper configuration"),
        (r'java\.util\.Random|Math\.random', 
         "Insecure random number generator used for cryptography"),
        (r'const val IV|static final byte\[\] IV|final static byte\[\] IV|String IV|static String IV',
         "Hardcoded Initialization Vector")
    ]
    
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
                        
                        for pattern, description in crypto_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                
                                # check for Cipher.getInstance to determine if its a weak config
                                if "Cipher.getInstance" in pattern:
                                    if "ECB" in context or not ("CBC" in context or "GCM" in context):
                                        description = "Potentially insecure cipher mode (not using CBC/GCM)"
                                    else:
                                        continue
                                
                                issues.append({
                                    "type": "Cryptography Issue",
                                    "severity": "HIGH",
                                    "description": description,
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for authentication and cryptography issues")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    auth_issues = analyze_authentication(args.decompiled_dir)
    crypto_issues = analyze_cryptography(args.decompiled_dir)
    
    all_issues = auth_issues + crypto_issues
    
    # print summary
    print(f"\nAnalysis complete! Found {len(all_issues)} potential auth/crypto issues:")
    print(f"- Authentication Issues: {len(auth_issues)} issues")
    print(f"- Cryptography Issues: {len(crypto_issues)} issues")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
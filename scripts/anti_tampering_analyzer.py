import os
import re
import argparse
import json

def check_signature_verification(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    signature_patterns = [
        (r'PackageManager\.GET_SIGNATURES', "Signature verification check"),
        (r'getPackageInfo\([^,]+,\s*PackageManager\.GET_SIGNATURES\)', "Signature verification check"),
        (r'X509Certificate|CertificateFactory\.getInstance\(', "Certificate validation"),
        (r'signature.*?verify|verify.*?signature', "Signature verification check"),
        (r'MessageDigest|digest\.update|digest\.digest', "Hash verification")
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
                        
                        for pattern, description in signature_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Anti-Tampering",
                                    "severity": "INFO",
                                    "description": f"Potential {description} detected",
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def check_root_detection(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    root_detection_patterns = [
        (r'/system/bin/su|/system/xbin/su|/sbin/su|/system/app/Superuser\.apk|/system/app/SuperSU\.apk', 
         "Root binary detection"),
        (r'test-keys', "Test keys detection"),
        (r'RootBeer|RootTools|Rootcloakplus|Rootchecker', "Root detection library"),
        (r'getRuntime\(\)\.exec\([^)]*su[^)]*\)', "Runtime execution check for su"),
        (r'Shell\.exec\([^)]*su[^)]*\)', "Shell execution check for su"),
        (r'RootDetection|detectRootedDevice|isDeviceRooted', "Root detection method")
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
                        
                        for pattern, description in root_detection_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Root Detection",
                                    "severity": "INFO",
                                    "description": f"Potential {description} mechanism found",
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def check_emulator_detection(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    emulator_detection_patterns = [
        (r'android\.os\.Build\.FINGERPRINT.*?generic|.*?sdk|.*?sdk_gphone', "Build fingerprint check"),
        (r'android\.os\.Build\.MODEL.*?sdk|.*?Emulator|.*?Android SDK', "Device model check"),
        (r'android\.os\.Build\.MANUFACTURER.*?Google|.*?Genymotion', "Manufacturer check"),
        (r'android\.os\.Build\.HARDWARE.*?goldfish|.*?ranchu', "Hardware check"),
        (r'android\.os\.Build\.PRODUCT.*?sdk|.*?google_sdk|.*?sdk_x86|.*?sdk_gphone', "Product check"),
        (r'isEmulator|detectEmulator|EmulatorDetector', "Emulator detection method"),
        (r'qemu|goldfish|x86_64|x86\.', "QEMU/emulator string check")
    ]
    
    total_files = 0
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                total_files += 1
        
    # set limits
    max_matches_per_file = 5
    max_files_with_matches = 20
    files_with_matches = 0
    processed_files = 0
    
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                processed_files += 1
                
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                # skip library code
                if "com/google/" in file_path or "androidx/" in file_path:
                    continue
                    
                try:
                    file_size = os.path.getsize(file_path)
                    
                    # skip excessively large files
                    if file_size > 1000000:
                        print(f"Skipping large file ({file_size} bytes): {rel_path}")
                        continue
                        
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        has_matches = False
                        match_count = 0
                        
                        for pattern, description in emulator_detection_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                has_matches = True
                                
                                if match_count < max_matches_per_file:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        match_count += 1
                                        if match_count > max_matches_per_file:
                                            break
                                            
                                        context = content[max(0, match.start() - 40):match.end() + 40]
                                        issues.append({
                                            "type": "Emulator Detection",
                                            "severity": "INFO",
                                            "description": f"Potential {description} found",
                                            "location": rel_path,
                                            "context": context.strip()
                                        })
                        
                        if has_matches:
                            files_with_matches += 1
                            
                        if files_with_matches >= max_files_with_matches:
                            print(f"Maximum number of files with matches ({max_files_with_matches}) reached. Stopping scan.")
                            return issues
                                
                except Exception as e:
                    print(f"Error processing file {rel_path}: {str(e)}")
                    continue
    
    return issues

def check_debugger_detection(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    debug_detection_patterns = [
        (r'Debug\.isDebuggerConnected\(\)', "Debugger connection check"),
        (r'android\.os\.Debug', "Debug class usage"),
        (r'isDebuggerConnected|AmIBeingDebugged', "Debugger detection method"),
        (r'android:debuggable="false"', "Explicit debug disabled flag"),
        (r'ActivityManager\.isUserAMonkey\(\)', "Test environment detection"),
        (r'attachBaseContext', "Potential runtime manipulation check")
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
                        
                        for pattern, description in debug_detection_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Anti-Debugging",
                                    "severity": "INFO",
                                    "description": f"Potential {description} detected",
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for anti-tampering mechanisms")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    signature_issues = check_signature_verification(args.decompiled_dir)
    root_issues = check_root_detection(args.decompiled_dir)
    emulator_issues = check_emulator_detection(args.decompiled_dir)
    debug_issues = check_debugger_detection(args.decompiled_dir)
    
    all_issues = signature_issues + root_issues + emulator_issues + debug_issues
    
    # print summary
    print(f"\nAnalysis complete! Found {len(all_issues)} potential anti-tampering mechanisms:")
    print(f"- Signature Verification: {len(signature_issues)} mechanisms")
    print(f"- Root Detection: {len(root_issues)} mechanisms")
    print(f"- Emulator Detection: {len(emulator_issues)} mechanisms")
    print(f"- Anti-Debugging: {len(debug_issues)} mechanisms")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
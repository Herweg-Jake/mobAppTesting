import os
import re
import argparse
import json
import xml.etree.ElementTree as ET

def check_backup_enabled(decompiled_dir):
    issues = []
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    
    if not os.path.exists(manifest_path):
        print("Warning: AndroidManifest.xml not found")
        return issues
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        # check backup attribute
        application = root.find(".//application", ns)
        if application is not None:
            backup_attr = application.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if backup_attr == "true" or backup_attr is None:
                issues.append({
                    "type": "Backup Enabled",
                    "severity": "MEDIUM",
                    "description": "App allows backups which could expose sensitive data",
                    "location": "AndroidManifest.xml"
                })
    except Exception as e:
        print(f"Error checking backup settings: {e}")
    
    return issues

def analyze_storage_issues(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # patterns for storage issues
    storage_patterns = [
        (r'getExternalStorage|getExternalFilesDir|Environment\.getExternalStorageDirectory', 
         "Using external storage which may expose sensitive data"),
        (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
         "Using insecure file permissions"),
        (r'openFileOutput\([^,]+,\s*0\)',
         "Creating file with default permissions (potentially insecure)"),
        (r'\.putString\([^,]*?(password|token|key|secret|cred)[^,]*?,',
         "Storing sensitive data in SharedPreferences"),
        (r'database\s*=\s*.*?openOrCreateDatabase\([^,]+,\s*0',
         "Creating database with default permissions"),
        (r'SQLiteDatabase\s*\.\s*openOrCreateDatabase\([^)]*\)',
         "Check for encrypted SQLite database usage"),
        (r'Cursor\s+.*?\s*=\s*.*?query\(',
         "Database query - check for proper encryption")
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
                        
                        for pattern, description in storage_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                context = content[max(0, match.start() - 40):match.end() + 40]
                                issues.append({
                                    "type": "Storage Issue",
                                    "severity": "MEDIUM",
                                    "description": description,
                                    "location": rel_path,
                                    "context": context.strip()
                                })
                except Exception as e:
                    continue
    
    return issues

def check_keyboard_cache(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    layout_dir = os.path.join(decompiled_dir, "resources", "res", "layout")
    
    # check layout xml files for inputType
    if os.path.exists(layout_dir):
        for root, _, files in os.walk(layout_dir):
            for file in files:
                if file.endswith(".xml"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, decompiled_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # look for input fields without noPersonalizedLearning
                            if ("EditText" in content or "TextInputLayout" in content) and \
                               ("password" in content.lower() or "credit" in content.lower() or 
                                "username" in content.lower() or "email" in content.lower()):
                                
                                if "android:inputType" in content and not "textNoSuggestions" in content:
                                    issues.append({
                                        "type": "Keyboard Cache",
                                        "severity": "LOW",
                                        "description": "Sensitive input field may allow keyboard suggestions/caching",
                                        "location": rel_path
                                    })
                    except Exception as e:
                        continue
    
    # check java for EditText configuration
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
                        
                        if ("EditText" in content or "TextInputLayout" in content) and \
                           ("password" in content.lower() or "credit" in content.lower() or
                            "username" in content.lower() or "email" in content.lower()):
                            
                            if "setInputType" in content and not "InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS" in content:
                                issues.append({
                                    "type": "Keyboard Cache",
                                    "severity": "LOW",
                                    "description": "Programmatically configured input field may allow keyboard suggestions",
                                    "location": rel_path
                                })
                except Exception as e:
                    continue
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for storage security issues")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    backup_issues = check_backup_enabled(args.decompiled_dir)
    storage_issues = analyze_storage_issues(args.decompiled_dir)
    keyboard_issues = check_keyboard_cache(args.decompiled_dir)
    
    all_issues = backup_issues + storage_issues + keyboard_issues
    
    # print summary
    print(f"\nAnalysis complete! Found {len(all_issues)} potential storage security issues:")
    print(f"- Backup Issues: {len(backup_issues)} issues")
    print(f"- Storage Issues: {len(storage_issues)} issues")
    print(f"- Keyboard Cache Issues: {len(keyboard_issues)} issues")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()

import os
import re
import argparse
import json
import xml.etree.ElementTree as ET

def extract_permissions(decompiled_dir):
    permissions = []
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    
    if not os.path.exists(manifest_path):
        print("Warning: AndroidManifest.xml not found")
        return permissions
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        # extract permissions
        for permission in root.findall(".//uses-permission", ns):
            perm_name = permission.get("{http://schemas.android.com/apk/res/android}name")
            if perm_name:
                permissions.append(perm_name)
                
        # permission groups
        for permission_group in root.findall(".//permission-group", ns):
            perm_group_name = permission_group.get("{http://schemas.android.com/apk/res/android}name")
            if perm_group_name:
                permissions.append(perm_group_name)
                
        #custom permissions
        for custom_permission in root.findall(".//permission", ns):
            custom_perm_name = custom_permission.get("{http://schemas.android.com/apk/res/android}name")
            if custom_perm_name:
                permissions.append(f"Custom: {custom_perm_name}")
                
    except Exception as e:
        print(f"Error extracting permissions: {e}")
    
    return permissions

def classify_permissions(permissions):
    dangerous_permissions = [
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    ]
    
    signature_permissions = [
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.BATTERY_STATS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_AUTOFILL_SERVICE",
        "android.permission.BIND_CARRIER_SERVICES",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_DREAM_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_PRINT_SERVICE",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.BLUETOOTH_PRIVILEGED",
        "android.permission.PACKAGE_USAGE_STATS"
    ]
    
    classified = {
        "dangerous": [],
        "signature": [],
        "normal": [],
        "custom": []
    }
    
    for permission in permissions:
        if permission in dangerous_permissions:
            classified["dangerous"].append(permission)
        elif permission in signature_permissions:
            classified["signature"].append(permission)
        elif permission.startswith("Custom:"):
            classified["custom"].append(permission)
        else:
            classified["normal"].append(permission)
    
    return classified

def analyze_permission_usage(decompiled_dir, permissions):
    java_dir = os.path.join(decompiled_dir, "sources")
    permission_usage = {}
    
    # map permissions to their common api usage patterns
    permission_patterns = {
        "android.permission.INTERNET": [r'HttpURLConnection|URL\.openConnection|Socket|OkHttp|Retrofit|HttpClient'],
        "android.permission.ACCESS_FINE_LOCATION": [r'getLastKnownLocation|requestLocationUpdates|FusedLocationProviderClient'],
        "android.permission.ACCESS_COARSE_LOCATION": [r'getLastKnownLocation|requestLocationUpdates|FusedLocationProviderClient'],
        "android.permission.CAMERA": [r'Camera\.|CameraManager|CameraDevice|cameraCaptureSessions'],
        "android.permission.READ_CONTACTS": [r'ContactsContract|getContentResolver\(\)\.query\([^)]*Contacts'],
        "android.permission.WRITE_CONTACTS": [r'ContactsContract|getContentResolver\(\)\.insert\([^)]*Contacts'],
        "android.permission.READ_EXTERNAL_STORAGE": [r'getExternalStorageDirectory|getExternalFilesDir|Environment\.getExternalStoragePublicDirectory'],
        "android.permission.WRITE_EXTERNAL_STORAGE": [r'getExternalStorageDirectory|getExternalFilesDir|Environment\.getExternalStoragePublicDirectory'],
        "android.permission.RECORD_AUDIO": [r'AudioRecord|MediaRecorder\.setAudioSource|startRecording'],
        "android.permission.SEND_SMS": [r'SmsManager\.send'],
        "android.permission.READ_SMS": [r'getContentResolver\(\)\.query\([^)]*sms'],
        "android.permission.RECEIVE_SMS": [r'android\.provider\.Telephony\.SMS_RECEIVED'],
        "android.permission.READ_PHONE_STATE": [r'TelephonyManager|getDeviceId|getImei|getLine1Number|getSubscriberId'],
        "android.permission.CALL_PHONE": [r'ACTION_CALL|Intent\([^)]*tel:'],
        "android.permission.READ_CALENDAR": [r'CalendarContract|getContentResolver\(\)\.query\([^)]*Calendar'],
        "android.permission.WRITE_CALENDAR": [r'CalendarContract|getContentResolver\(\)\.insert\([^)]*Calendar']
    }
    
    # initialize usage tracking for each permission
    for permission in permissions:
        short_name = permission.split(".")[-1] if "." in permission else permission
        permission_usage[permission] = {
            "used": False,
            "evidence": [],
            "usage_count": 0,
            "short_name": short_name
        }
    
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
                        
                        for permission, patterns in permission_patterns.items():
                            if permission in permissions:
                                for pattern in patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        context = content[max(0, match.start() - 30):match.end() + 30].strip()
                                        
                                        # update permission usage
                                        permission_usage[permission]["used"] = True
                                        permission_usage[permission]["usage_count"] += 1
                                        
                                        if len(permission_usage[permission]["evidence"]) < 3:
                                            permission_usage[permission]["evidence"].append({
                                                "file": rel_path,
                                                "context": context
                                            })
                except Exception as e:
                    continue
    
    return permission_usage

def find_permission_issues(permissions, permission_usage):
    issues = []
    
    # check for unused dangerous permissions
    for permission in permissions:
        if permission in permission_usage:
            data = permission_usage[permission]
            
            if permission in [p for p, d in permission_usage.items() if not d["used"] and p.startswith("android.permission.")]:
                short_name = data["short_name"]
                issues.append({
                    "type": "Unused Permission",
                    "severity": "MEDIUM",
                    "description": f"Permission {short_name} is requested but appears unused in code",
                    "location": "AndroidManifest.xml",
                    "context": f"The app requests the {short_name} permission but no usage was detected in code"
                })
    
    # check for dangerous permissions
    dangerous_count = len([p for p in permissions if p in permission_usage and p.startswith("android.permission.") and p in permission_usage])
    if dangerous_count >= 5:
        issues.append({
            "type": "Excessive Permissions",
            "severity": "MEDIUM",
            "description": f"App requests {dangerous_count} dangerous permissions which may raise privacy concerns",
            "location": "AndroidManifest.xml",
            "context": f"The app requests multiple dangerous permissions including: " + 
                      ", ".join([permission_usage[p]["short_name"] for p in permissions 
                               if p in permission_usage and p.startswith("android.permission.")])[:100] + "..."
        })
    
    # check for custom permissions
    custom_perms = [p for p in permissions if p.startswith("Custom:")]
    if custom_perms:
        issues.append({
            "type": "Custom Permissions",
            "severity": "INFO",
            "description": f"App defines {len(custom_perms)} custom permissions",
            "location": "AndroidManifest.xml",
            "context": "Custom permissions may expose functionality to other apps if not properly protected"
        })
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze permissions in decompiled APK")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    permissions = extract_permissions(args.decompiled_dir)
    classified_perms = classify_permissions(permissions)
    permission_usage = analyze_permission_usage(args.decompiled_dir, permissions)
    issues = find_permission_issues(permissions, permission_usage)
    
    # print summary
    print(f"\nPermission Analysis Complete!")
    print(f"Total permissions: {len(permissions)}")
    print(f"- Dangerous permissions: {len(classified_perms['dangerous'])}")
    print(f"- Signature permissions: {len(classified_perms['signature'])}")
    print(f"- Normal permissions: {len(classified_perms['normal'])}")
    print(f"- Custom permissions: {len(classified_perms['custom'])}")
    
    used_count = len([p for p in permission_usage.values() if p["used"]])
    unused_count = len(permissions) - used_count
    print(f"\nPermission Usage:")
    print(f"- Used permissions: {used_count}")
    print(f"- Unused permissions: {unused_count}")
    
    print(f"\nFound {len(issues)} permission-related issues")
    
    results = {
        "permissions": classified_perms,
        "usage": permission_usage,
        "issues": issues
    }
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
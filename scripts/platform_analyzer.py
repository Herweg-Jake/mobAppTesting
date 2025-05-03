import os
import re
import argparse
import json
import xml.etree.ElementTree as ET

def check_webview_security(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # patterns for webview issues
    webview_patterns = [
        (r'setJavaScriptEnabled\(true\)', 
         "JavaScript enabled in WebView which may lead to XSS"),
        (r'addJavascriptInterface\([^,]+,\s*["\'][^"\']+["\']\)',
         "JavaScript interface exposed to WebView without proper validation"),
        (r'setAllowFileAccess\(true\)',
         "File access enabled in WebView which may lead to local file inclusion"),
        (r'setAllowContentAccess\(true\)',
         "Content access enabled in WebView which may expose content providers"),
        (r'setAllowFileAccessFromFileURLs\(true\)',
         "File URL access enabled which may lead to local file inclusion"),
        (r'setDomStorageEnabled\(true\)',
         "DOM storage enabled in WebView which may store sensitive data"),
        (r'setSavePassword\(true\)',
         "Password saving enabled in WebView which may store credentials"),
        (r'onReceivedSslError[^{]*\{[^}]*proceed',
         "SSL errors ignored in WebView which defeats HTTPS protections")
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
                        
                        # check if file contains webview
                        if "WebView" in content:
                            for pattern, description in webview_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    context = content[max(0, match.start() - 40):match.end() + 40]
                                    issues.append({
                                        "type": "WebView Issue",
                                        "severity": "HIGH",
                                        "description": description,
                                        "location": rel_path,
                                        "context": context.strip()
                                    })
                except Exception as e:
                    continue
    
    return issues

def check_exported_components(decompiled_dir):
    issues = []
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    
    if not os.path.exists(manifest_path):
        print("Warning: AndroidManifest.xml not found")
        return issues
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        # check for exported components (activities, services, receivers, providers)
        components = [
            ("activity", "Activity"),
            ("service", "Service"),
            ("receiver", "Broadcast Receiver"),
            ("provider", "Content Provider")
        ]
        
        for tag, component_type in components:
            for component in root.findall(f".//*/{tag}", ns):
                exported = component.get("{http://schemas.android.com/apk/res/android}exported")
                name = component.get("{http://schemas.android.com/apk/res/android}name")
                
                # check if component has intent filters (implicitly exported)
                has_intent_filter = component.find(".//intent-filter") is not None
                
                # check permission attribute
                permission = component.get("{http://schemas.android.com/apk/res/android}permission")
                
                is_exported = exported == "true" or (has_intent_filter and exported != "false")
                
                if is_exported:
                    # check if exported component has a permission defined
                    if not permission:
                        issues.append({
                            "type": "Exported Component",
                            "severity": "HIGH",
                            "description": f"{component_type} '{name}' is exported without permission protection",
                            "location": "AndroidManifest.xml"
                        })
    except Exception as e:
        print(f"Error checking exported components: {e}")
    
    return issues

def check_deep_links(decompiled_dir):
    issues = []
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    
    if not os.path.exists(manifest_path):
        print("Warning: AndroidManifest.xml not found")
        return issues
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        # find all intent filters with data elements (deep links)
        for intent_filter in root.findall(".//*//intent-filter", ns):
            data_elements = intent_filter.findall(".//data", ns)
            
            if data_elements:
                parent = intent_filter.getparent()
                component_name = parent.get("{http://schemas.android.com/apk/res/android}name")
                
                exported = parent.get("{http://schemas.android.com/apk/res/android}exported")
                
                if exported != "false":
                    # check if permission is defined
                    permission = parent.get("{http://schemas.android.com/apk/res/android}permission")
                    
                    if not permission:
                        schemes = []
                        hosts = []
                        
                        for data in data_elements:
                            scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                            host = data.get("{http://schemas.android.com/apk/res/android}host")
                            
                            if scheme:
                                schemes.append(scheme)
                            if host:
                                hosts.append(host)
                        
                        schemes_str = ", ".join(schemes) if schemes else "any"
                        hosts_str = ", ".join(hosts) if hosts else "any"
                        
                        issues.append({
                            "type": "Deep Link Issue",
                            "severity": "MEDIUM",
                            "description": f"Deep link handler '{component_name}' is accessible without permission protection (schemes: {schemes_str}, hosts: {hosts_str})",
                            "location": "AndroidManifest.xml"
                        })
    except Exception as e:
        print(f"Error checking deep links: {e}")
    
    return issues

def check_flag_secure(decompiled_dir):
    issues = []
    java_dir = os.path.join(decompiled_dir, "sources")
    
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
                        
                        if ("extends Activity" in content or "extends AppCompatActivity" in content or 
                            ": Activity(" in content or ": AppCompatActivity(" in content):
                            
                            # check if sensitive screen
                            is_sensitive = any(term in content.lower() for term in 
                                             ["password", "login", "auth", "credit", "payment", "secure", 
                                              "personal", "profile", "account"])
                            
                            # check if FLAG_SECURE is set
                            if is_sensitive and "FLAG_SECURE" not in content:
                                issues.append({
                                    "type": "Missing FLAG_SECURE",
                                    "severity": "MEDIUM",
                                    "description": "Sensitive screen missing FLAG_SECURE, allowing screenshots and screen recording",
                                    "location": rel_path
                                })
                except Exception as e:
                    continue
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze decompiled APK for platform API security issues")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    webview_issues = check_webview_security(args.decompiled_dir)
    component_issues = check_exported_components(args.decompiled_dir)
    deeplink_issues = check_deep_links(args.decompiled_dir)
    flag_secure_issues = check_flag_secure(args.decompiled_dir)
    
    all_issues = webview_issues + component_issues + deeplink_issues + flag_secure_issues
    
    # print summary
    print(f"\nAnalysis complete! Found {len(all_issues)} potential platform API security issues:")
    print(f"- WebView Issues: {len(webview_issues)} issues")
    print(f"- Exported Component Issues: {len(component_issues)} issues")
    print(f"- Deep Link Issues: {len(deeplink_issues)} issues")
    print(f"- FLAG_SECURE Issues: {len(flag_secure_issues)} issues")
    
    # save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_issues, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
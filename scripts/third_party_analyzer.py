import os
import re
import argparse
import json

def detect_libraries(decompiled_dir):
    libraries = {}
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # common libraries and their detection patterns
    library_patterns = {
        "Retrofit": [r'retrofit2|com\.squareup\.retrofit'],
        "OkHttp": [r'okhttp3|com\.squareup\.okhttp'],
        "Volley": [r'com\.android\.volley'],
        "Gson": [r'com\.google\.gson'],
        "Jackson": [r'com\.fasterxml\.jackson'],
        "Picasso": [r'com\.squareup\.picasso'],
        "Glide": [r'com\.bumptech\.glide'],
        "Firebase": [r'com\.google\.firebase'],
        "Facebook SDK": [r'com\.facebook\.'],
        "Google Maps": [r'com\.google\.android\.gms\.maps'],
        "Crashlytics": [r'com\.crashlytics|io\.fabric'],
        "Lottie": [r'com\.airbnb\.lottie'],
        "ZXing": [r'com\.google\.zxing'],
        "ReactiveX": [r'io\.reactivex'],
        "Realm": [r'io\.realm'],
        "Butterknife": [r'butterknife'],
        "Dagger": [r'dagger'],
        "Kotlin Coroutines": [r'kotlinx\.coroutines'],
        "ExoPlayer": [r'com\.google\.android\.exoplayer'],
        "Admob": [r'com\.google\.android\.gms\.ads'],
        "OneSignal": [r'com\.onesignal'],
        "AWS SDK": [r'com\.amazonaws'],
        "Stetho": [r'com\.facebook\.stetho']
    }
    
    for library_name in library_patterns:
        libraries[library_name] = {
            "detected": False,
            "files": [],
            "import_count": 0
        }
    
    # search for library imports
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for library_name, patterns in library_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    libraries[library_name]["detected"] = True
                                    
                                    if rel_path not in libraries[library_name]["files"]:
                                        libraries[library_name]["files"].append(rel_path)
                                    
                                    # count imports
                                    imports = re.findall(r'import\s+(' + pattern + r'[^;]*);', content, re.IGNORECASE)
                                    libraries[library_name]["import_count"] += len(imports)
                except Exception as e:
                    continue
    
    detected_libraries = {name: data for name, data in libraries.items() if data["detected"]}
    
    return detected_libraries

def detect_ad_networks(decompiled_dir):
    ad_networks = {}
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # common ad networks
    ad_patterns = {
        "AdMob": [r'com\.google\.android\.gms\.ads'],
        "Facebook Audience Network": [r'com\.facebook\.ads'],
        "AppLovin": [r'com\.applovin'],
        "Unity Ads": [r'com\.unity3d\.ads|UnityAds'],
        "MoPub": [r'com\.mopub'],
        "Chartboost": [r'com\.chartboost'],
        "InMobi": [r'com\.inmobi'],
        "Tapjoy": [r'com\.tapjoy'],
        "ironSource": [r'com\.ironsource'],
        "Vungle": [r'com\.vungle'],
        "AdColony": [r'com\.adcolony']
    }
    
    for network_name in ad_patterns:
        ad_networks[network_name] = {
            "detected": False,
            "evidence": []
        }
    
    # search for ad networks
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for network_name, patterns in ad_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    context = content[max(0, match.start() - 40):match.end() + 40].strip()
                                    ad_networks[network_name]["detected"] = True
                                    
                                    # Add first 3 evidence examples at most
                                    if len(ad_networks[network_name]["evidence"]) < 3:
                                        ad_networks[network_name]["evidence"].append({
                                            "file": rel_path,
                                            "context": context
                                        })
                except Exception as e:
                    continue
    
    detected_ad_networks = {name: data for name, data in ad_networks.items() if data["detected"]}
    
    return detected_ad_networks

def detect_tracking_libraries(decompiled_dir):
    tracking_libs = {}
    java_dir = os.path.join(decompiled_dir, "sources")
    
    # common tracking libraries
    tracking_patterns = {
        "Google Analytics": [r'com\.google\.android\.gms\.analytics'],
        "Firebase Analytics": [r'com\.google\.firebase\.analytics'],
        "Flurry": [r'com\.flurry'],
        "Mixpanel": [r'com\.mixpanel'],
        "Amplitude": [r'com\.amplitude'],
        "Crashlytics": [r'com\.crashlytics|io\.fabric\.sdk\.android\.Fabric'],
        "Appsflyer": [r'com\.appsflyer'],
        "Adjust": [r'com\.adjust\.sdk'],
        "Branch": [r'io\.branch'],
        "Segment": [r'com\.segment'],
        "Lokalise": [r'com\.lokalise'],
        "Leanplum": [r'com\.leanplum']
    }
    
    for lib_name in tracking_patterns:
        tracking_libs[lib_name] = {
            "detected": False,
            "evidence": []
        }
    
    # search for tracking libraries
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".kt"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompiled_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for lib_name, patterns in tracking_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    context = content[max(0, match.start() - 40):match.end() + 40].strip()
                                    tracking_libs[lib_name]["detected"] = True
                                    
                                    if len(tracking_libs[lib_name]["evidence"]) < 3:
                                        tracking_libs[lib_name]["evidence"].append({
                                            "file": rel_path,
                                            "context": context
                                        })
                except Exception as e:
                    continue
    
    detected_tracking_libs = {name: data for name, data in tracking_libs.items() if data["detected"]}
    
    return detected_tracking_libs

def find_library_issues(libraries, ad_networks, tracking_libs):
    issues = []
    
    # check for excessive tracking
    tracking_count = len(tracking_libs)
    if tracking_count >= 3:
        issues.append({
            "type": "Excessive Tracking",
            "severity": "MEDIUM",
            "description": f"App uses {tracking_count} different analytics/tracking libraries",
            "location": "Multiple files",
            "context": f"Detected tracking libraries: {', '.join(tracking_libs.keys())}"
        })
    
    # check for multiple ad networks
    ad_network_count = len(ad_networks)
    if ad_network_count >= 2:
        issues.append({
            "type": "Multiple Ad Networks",
            "severity": "LOW",
            "description": f"App uses {ad_network_count} different ad networks",
            "location": "Multiple files",
            "context": f"Detected ad networks: {', '.join(ad_networks.keys())}"
        })
    
    network_libs = []
    for lib_name in ["Retrofit", "OkHttp", "Volley"]:
        if lib_name in libraries and libraries[lib_name]["detected"]:
            network_libs.append(lib_name)
    
    if network_libs:
        issues.append({
            "type": "Network Libraries",
            "severity": "INFO",
            "description": f"App uses {', '.join(network_libs)} for network communication",
            "location": "Multiple files",
            "context": "Review these implementations to ensure secure communication practices"
        })
    
    return issues

def main():
    parser = argparse.ArgumentParser(description="Analyze third-party libraries in decompiled APK")
    parser.add_argument("decompiled_dir", help="Path to the decompiled APK directory")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    libraries = detect_libraries(args.decompiled_dir)
    ad_networks = detect_ad_networks(args.decompiled_dir)
    tracking_libs = detect_tracking_libraries(args.decompiled_dir)
    issues = find_library_issues(libraries, ad_networks, tracking_libs)
    
    # print summary
    print(f"\nThird-Party Library Analysis Complete!")
    print(f"Detected {len(libraries)} libraries:")
    for lib_name in libraries.keys():
        print(f"- {lib_name}")
    
    print(f"\nAd Networks: {len(ad_networks)}")
    for network in ad_networks.keys():
        print(f"- {network}")
    
    print(f"\nTracking/Analytics Libraries: {len(tracking_libs)}")
    for lib in tracking_libs.keys():
        print(f"- {lib}")
    
    print(f"\nFound {len(issues)} library-related issues")
    
    results = {
        "libraries": libraries,
        "ad_networks": ad_networks,
        "tracking_libraries": tracking_libs,
        "issues": issues
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    main()
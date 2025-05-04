import os
import argparse
import subprocess
import time
import json
from pathlib import Path

def run_analysis(apk_path, output_dir=None):    
    start_time = time.time()
    
    if not output_dir:
        app_name = os.path.basename(apk_path).split('.')[0]
        output_dir = f"security_analysis_{app_name}"
    
    Path(output_dir).mkdir(exist_ok=True)
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # decompile the apk
    print("\n[1/6] Decompiling APK...")
    decompile_script = os.path.join(script_dir, "apk_decompiler.py")
    decompiled_dir = os.path.join(output_dir, "decompiled")
    subprocess.run(["python", decompile_script, apk_path, "-o", decompiled_dir])
    
    if not os.path.exists(decompiled_dir):
        print("Error: Decompilation failed. Exiting.")
        return
    
    # results directory
    results_dir = os.path.join(output_dir, "results")
    Path(results_dir).mkdir(exist_ok=True)
    
    # run basic security analyzer
    print("\n[2/10] Running base security analyzer...")
    security_analyzer = os.path.join(script_dir, "security_analyzer.py")
    base_results = os.path.join(results_dir, "base_security.json")
    subprocess.run(["python", security_analyzer, decompiled_dir, "-o", base_results])
    
    # run log and memory analyzer
    print("\n[3/10] Analyzing log and memory security...")
    log_memory_analyzer = os.path.join(script_dir, "log_memory_analyzer.py")
    log_memory_results = os.path.join(results_dir, "log_memory_security.json")
    subprocess.run(["python", log_memory_analyzer, decompiled_dir, "-o", log_memory_results])
    
    # run authentication and crypto analyzer
    print("\n[4/10] Analyzing authentication and cryptography...")
    auth_crypto_analyzer = os.path.join(script_dir, "auth_crypto_analyzer.py")
    auth_crypto_results = os.path.join(results_dir, "auth_crypto_security.json")
    subprocess.run(["python", auth_crypto_analyzer, decompiled_dir, "-o", auth_crypto_results])
    
    # run storage analyzer
    print("\n[5/10] Analyzing storage security...")
    storage_analyzer = os.path.join(script_dir, "storage_analyzer.py")
    storage_results = os.path.join(results_dir, "storage_security.json")
    subprocess.run(["python", storage_analyzer, decompiled_dir, "-o", storage_results])
    
    # run platform api analyzer
    print("\n[6/10] Analyzing platform API security...")
    platform_analyzer = os.path.join(script_dir, "platform_analyzer.py")
    platform_results = os.path.join(results_dir, "platform_security.json")
    subprocess.run(["python", platform_analyzer, decompiled_dir, "-o", platform_results])
    
    # run anti-tampering analyzer
    print("\n[7/10] Analyzing anti-tampering mechanisms...")
    anti_tampering_analyzer = os.path.join(script_dir, "anti_tampering_analyzer.py")
    anti_tampering_results = os.path.join(results_dir, "anti_tampering.json")
    subprocess.run(["python", anti_tampering_analyzer, decompiled_dir, "-o", anti_tampering_results])
    
    # run permission analyzer
    print("\n[8/10] Analyzing app permissions...")
    permission_analyzer = os.path.join(script_dir, "permission_analyzer.py")
    permission_results = os.path.join(results_dir, "permissions.json")
    subprocess.run(["python", permission_analyzer, decompiled_dir, "-o", permission_results])
    
    # run third-party library analyzer
    print("\n[9/10] Analyzing third-party libraries...")
    library_analyzer = os.path.join(script_dir, "third_party_analyzer.py")
    library_results = os.path.join(results_dir, "libraries.json")
    subprocess.run(["python", library_analyzer, decompiled_dir, "-o", library_results])
    
    # generate report
    print("\n[10/10] Generating final report...")
    app_name = os.path.basename(apk_path).split('.')[0]
    report_generator = os.path.join(script_dir, "security_visualizer.py")
    report_path = os.path.join(output_dir, "security_report.html")
    
    result_files = [
        base_results,
        log_memory_results,
        auth_crypto_results,
        storage_results,
        platform_results,
        anti_tampering_results,
        permission_results,
        library_results
    ]
    
    # filter only existing result files
    existing_result_files = [f for f in result_files if os.path.exists(f)]
    
    subprocess.run([
        "python", 
        report_generator, 
        app_name, 
        *existing_result_files,
        "-o", report_path
    ])
    
    # get total issues
    total_issues = 0
    for result_file in existing_result_files:
        try:
            with open(result_file, 'r') as f:
                result_data = json.load(f)
                if isinstance(result_data, list):
                    total_issues += len(result_data)
                elif isinstance(result_data, dict) and "issues" in result_data:
                    total_issues += len(result_data["issues"])
        except:
            pass
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nAnalysis complete!")
    print(f"Total issues found: {total_issues}")
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Report saved to: {report_path}")
    print(f"You can open this HTML file in any web browser to view the results.")

def main():
    parser = argparse.ArgumentParser(description="Run comprehensive security analysis on an android apk")
    parser.add_argument("apk_path", help="Path to the apk file")
    parser.add_argument("-o", "--output", help="Output directory (optional)")
    
    args = parser.parse_args()
    
    run_analysis(args.apk_path, args.output)

if __name__ == "__main__":
    main()
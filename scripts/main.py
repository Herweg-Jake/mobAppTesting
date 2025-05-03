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
    
    # run all analyzers
    print("\n[2/6] Running base security analyzer...")
    security_analyzer = os.path.join(script_dir, "security_analyzer.py")
    base_results = os.path.join(results_dir, "base_security.json")
    subprocess.run(["python", security_analyzer, decompiled_dir, "-o", base_results])
    
    print("\n[3/6] Analyzing log and memory security...")
    log_memory_analyzer = os.path.join(script_dir, "log_memory_analyzer.py")
    log_memory_results = os.path.join(results_dir, "log_memory_security.json")
    subprocess.run(["python", log_memory_analyzer, decompiled_dir, "-o", log_memory_results])
    
    print("\n[4/6] Analyzing authentication and cryptography...")
    auth_crypto_analyzer = os.path.join(script_dir, "auth_crypto_analyzer.py")
    auth_crypto_results = os.path.join(results_dir, "auth_crypto_security.json")
    subprocess.run(["python", auth_crypto_analyzer, decompiled_dir, "-o", auth_crypto_results])
    
    print("\n[5/6] Analyzing storage security...")
    storage_analyzer = os.path.join(script_dir, "storage_analyzer.py")
    storage_results = os.path.join(results_dir, "storage_security.json")
    subprocess.run(["python", storage_analyzer, decompiled_dir, "-o", storage_results])
    
    print("\n[6/6] Analyzing platform API security...")
    platform_analyzer = os.path.join(script_dir, "platform_analyzer.py")
    platform_results = os.path.join(results_dir, "platform_security.json")
    subprocess.run(["python", platform_analyzer, decompiled_dir, "-o", platform_results])
    
    # generate report
    print("\nGenerating final report...")
    app_name = os.path.basename(apk_path).split('.')[0]
    report_generator = os.path.join(script_dir, "security_visualizer.py")
    report_path = os.path.join(output_dir, "security_report.html")
    
    result_files = [
        base_results,
        log_memory_results,
        auth_crypto_results,
        storage_results,
        platform_results
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
                issues = json.load(f)
                if isinstance(issues, list):
                    total_issues += len(issues)
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
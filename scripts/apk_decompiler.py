import os
import subprocess
import argparse
from pathlib import Path

def decompile_apk(apk_path, output_dir=None):    
    apk_path = os.path.abspath(apk_path)
    
    # check if apk exists
    if not os.path.isfile(apk_path):
        print(f"Error: APK file not found: {apk_path}")
        return None
    
    if not output_dir:
        apk_name = os.path.basename(apk_path).split('.')[0]
        output_dir = f"decompiled_{apk_name}"
    
    # Make sure output directory exists
    Path(output_dir).mkdir(exist_ok=True)
    output_dir = os.path.abspath(output_dir)
    
    print(f"Decompiling {apk_path} to {output_dir}...")
    
    # run jadx to decompile the apk
    try:
        # -j option to specify the number of threads
        cmd = [
            "jadx",
            "-j", "4",  # using 4 threads
            "--show-bad-code",
            "--deobf",
            "-d", output_dir,
            apk_path
        ]
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error during decompilation: {result.stderr}")
            return None
            
        print(f"Decompilation successful! Decompiled code is in {output_dir}")
        return output_dir
    except FileNotFoundError:
        print("Error: JADX not found. Please install JADX or check your PATH settings.")
        print("  Install with: sudo apt-get install jadx")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decompile APK files using JADX")
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("-o", "--output", help="Output directory (optional)")
    
    args = parser.parse_args()
    
    decompile_apk(args.apk_path, args.output)
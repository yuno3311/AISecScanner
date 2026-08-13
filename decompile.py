import sys
import os
import re
import json
import subprocess
from pathlib import Path

def sanitize_windows_path(path_str):
    """Converts paths to absolute local Windows paths, eliminating UNC/network resolution bugs."""
    p = Path(path_str).resolve()
    return str(p)

def setup_portable_environment(app_root):
    env = os.environ.copy()
    
    # Locate JDK 21 in root
    jdk_path = app_root / "jdk-21_windows-x64_bin"
    if not jdk_path.exists():
        for item in app_root.iterdir():
            if item.is_dir() and "jdk" in item.name.lower():
                jdk_path = item
                break
                
    if jdk_path.exists():
        env["JAVA_HOME"] = sanitize_windows_path(jdk_path)
        env["PATH"] = sanitize_windows_path(jdk_path / "bin") + os.pathsep + env.get("PATH", "")

    env["PATH"] = sanitize_windows_path(app_root) + os.pathsep + env.get("PATH", "")
    return env

def run_ghidra_headless(target_exe, ghidra_dir, raw_output_c, app_root):
    ghidra_path = Path(ghidra_dir)
    analyze_headless = ghidra_path / "support" / ("analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless")
    
    if not analyze_headless.exists():
        sys.stderr.write(f"analyzeHeadless.bat not found at: {analyze_headless}\n")
        return False

    # Create temporary project inside local workspace (NOT UNC)
    project_dir = app_root / "ghidra_tmp_proj"
    project_dir.mkdir(exist_ok=True)
    
    script_dir = app_root / "ghidra"
    
    cmd = [
        sanitize_windows_path(analyze_headless),
        sanitize_windows_path(project_dir),
        "TempProject",
        "-import", sanitize_windows_path(target_exe),
        "-scriptPath", sanitize_windows_path(script_dir),
        "-postScript", "ghidra_extract.py", sanitize_windows_path(raw_output_c),
        "-deleteProject"
    ]
    
    env = setup_portable_environment(app_root)
    
    # Set current working directory explicitly to local app_root to block network path fallback
    result = subprocess.run(
        cmd, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        text=True, 
        env=env,
        cwd=sanitize_windows_path(app_root)
    )
    
    if result.returncode != 0:
        sys.stderr.write(f"Ghidra Process Failed (Exit Code {result.returncode}):\n{result.stderr}\n")
        return False
        
    return True

def slice_and_clean_c(raw_output_c):
    if not os.path.exists(raw_output_c):
        return {}
        
    with open(raw_output_c, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    content = re.sub(r'/\* WARNING: .*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'/\* 0x[0-9a-fA-F]+ \*/', '', content)
    content = re.sub(r'undefined[0-9]*', 'void*', content)

    functions = {}
    matches = re.findall(r'// FUNCTION_START: (.*?)\n(.*?)// FUNCTION_END', content, re.DOTALL)
    for name, code in matches:
        cleaned_code = code.strip()
        if len(cleaned_code.splitlines()) > 3:
            functions[name.strip()] = cleaned_code

    return functions

def main():
    try:
        app_root = Path(__file__).parent.resolve()

        if len(sys.argv) < 3:
            print(json.dumps({"error": f"Invalid arguments passed to decompile.py: {sys.argv}"}), flush=True)
            sys.exit(1)
            
        target_exe = sys.argv[1]
        ghidra_dir = sys.argv[2]
        raw_c_file = sanitize_windows_path(app_root / "temp_decompiled.c")
        
        if not os.path.exists(target_exe):
            print(json.dumps({"error": f"Target binary does not exist: {target_exe}"}), flush=True)
            sys.exit(1)

        success = run_ghidra_headless(target_exe, ghidra_dir, raw_c_file, app_root)
        if not success:
            print(json.dumps({"error": "Ghidra headless execution failed. Check Stderr log for details."}), flush=True)
            sys.exit(1)
            
        functions = slice_and_clean_c(raw_c_file)
        
        print(json.dumps(functions), flush=True)

        if os.path.exists(raw_c_file):
            try:
                os.remove(raw_c_file)
            except OSError:
                pass

    except Exception as e:
        print(json.dumps({"error": f"Python Exception: {str(e)}"}), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
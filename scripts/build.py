#!/usr/bin/env python3
"""
AD Hardening Guidebook - Unified Build & Orchestration Engine
Supports incremental caching for script extraction, compliance generation,
markdown compilation, and PDF rendering.
"""

import os
import sys
import time
import shutil
import subprocess
import argparse

def run_step(name, cmd, cwd=None):
    start_time = time.time()
    print(f"\n========================================================")
    print(f"[*] Step: {name}")
    print(f"========================================================")
    
    result = subprocess.run(cmd, cwd=cwd)
    duration = time.time() - start_time
    
    if result.returncode != 0:
        print(f"\n[!] ERROR in step '{name}' (Exit Code: {result.returncode}) after {duration:.2f}s")
        sys.exit(result.returncode)
    else:
        print(f"[+] Completed: {name} ({duration:.2f}s)")
    return duration

def main():
    parser = argparse.ArgumentParser(description="Active Directory Hardening Guidebook Build System")
    parser.add_argument("--all", "--force", "-f", action="store_true", help="Force clean full rebuild of all artifacts")
    parser.add_argument("--pdf", action="store_true", help="Include PDF compilation step")
    parser.add_argument("--check", action="store_true", help="Run verification and syntax linting")
    parser.add_argument("--clean", action="store_true", help="Clean cache and build artifacts")
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cache_dir = os.path.join(repo_root, ".cache")

    if args.clean:
        print("[*] Cleaning build cache and temporary artifacts...")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            print("  Removed .cache directory.")
        print("[+] Clean completed.")
        return

    total_start = time.time()
    flag = ["--force"] if args.all else []

    # 1. Extract PowerShell Scripts
    run_step("Extract PowerShell Scripts", [sys.executable, "scripts/extract_scripts.py"] + flag, cwd=repo_root)

    # 2. Rebuild GitBook Summary
    run_step("Generate GitBook Summary", [sys.executable, "scripts/generate_summary.py"], cwd=repo_root)

    # 3. Rebuild Compliance Benchmarks (OVAL & XCCDF)
    run_step("Generate Compliance Benchmarks", [sys.executable, "scripts/generate_compliance.py"] + flag, cwd=repo_root)

    # 4. Compile Consolidated Guidebook Markdown
    run_step("Compile Guidebook Markdown", [sys.executable, "scripts/compile_docs.py"] + flag, cwd=repo_root)

    # 5. Optional PDF Generation
    if args.pdf:
        pdf_flags = ["--force"] if args.all else []
        node_exec = shutil.which("node") or "node"
        run_step("Generate Guidebook PDF", [node_exec, "scripts/generate_pdf.js"] + pdf_flags, cwd=repo_root)

    # 6. Optional Verification
    if args.check:
        pwsh_exec = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
        verify_flags = ["-Force"] if args.all else []
        run_step("Verify Documentation & Code Blocks", [pwsh_exec, "-File", "Verify-ADHardeningDocs.ps1"] + verify_flags, cwd=repo_root)

    total_duration = time.time() - total_start
    mode = "Full Rebuild" if args.all else "Incremental"
    print(f"\n========================================================")
    print(f"[OK] Build Succeeded ({mode}) in {total_duration:.2f}s")
    print(f"========================================================\n")

if __name__ == "__main__":
    main()

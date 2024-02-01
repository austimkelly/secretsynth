import subprocess

# Summary of this function:
# Run gitleaks in each repository. See
#
# Parameters:
# target is the owner of the repository
# repo_name is the name of the repository
# repo_path is the path, relative to this script, to the repository
# report_output_dir is the path, relative to this script, to the report file
# dry_run (optional, default=False) is a boolean that indicates whether or not to actually run the scan
# logger (optional, default=None) is a logger object to use for error logging
def do_gitleaks_scan(target, 
                     repo_name, 
                     repo_path, 
                     report_output_dir, 
                     dry_run=False, 
                     logger=None):
    # Run gitleaks in each repository. See https://github.com/gitleaks/gitleaks?tab=readme-ov-file#usage
    print(f"Running gitleaks on {repo_path} ...")
    command = [
        "gitleaks",
        "detect",
        "-f", # --report-format string
        "csv",
        "-r", # --report-path string
        f"{report_output_dir}/gitleaks_findings_{target}_{repo_name}.csv",
        "--source",
        f"{repo_path}",
        "-c", # --config string
        "./.gitleaks.toml", 
        #"-v"
    ]
    print("gitleaks command:", " ".join(command))
    if not dry_run:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        print(result.stdout)
        #print(result.stderr)

        if result.returncode != 0:
            print(f"gitleaks command returned non-zero exit status {result.returncode}")
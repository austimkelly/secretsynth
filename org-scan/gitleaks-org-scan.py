#gitleaks-org-scan.py
# License: MIT License

import os
import requests
import subprocess
import glob
import pandas as pd
from urllib.parse import urlparse
import argparse
import shutil
from datetime import datetime
import csv
import json
import sys

# import all functions our helper modules
from csv_coalesce import *
from ghas_secret_alerts_fetch import *

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--clean", action="store_true", help="delete the directories ./checkouts and ./reports. When --clean is present all other commands are ignored.")
parser.add_argument("--dry-run", action="store_true", help="run the script in dry run mode, don't execute any commands")
parser.add_argument("--org-type", choices=["users", "orgs"], help="set the organization type")
parser.add_argument("--owners", type=str, help="comma-delimited list of owners")
args = parser.parse_args()

# If --clean is not used, --org-type and --owners are required
if not args.clean and (args.org_type is None or args.owners is None):
    parser.error("--org-type and --owners are required unless --clean is used")

DRY_RUN = args.dry_run  # Set to True if --dry-run is present, False otherwise
print(f"DRY_RUN={DRY_RUN}")

ORG_TYPE = args.org_type if args.org_type else None # This can be "users" or "orgs"
TARGETS = args.owners.split(",") if args.owners else None  # Split the value of --owners into a list if present, None otherwise
TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')
CHECKOUT_DIR = "./checkout"  # This is the directory where the repositories will be cloned
GITLEAKS_REPORTS_DIR = "./gitleaks_reports"  # This is the directory where the gitleaks reports (per repo) will be saved

timestamp = datetime.now().strftime('%Y%m%d%H%M')
REPORTS_DIR = f"./reports/reports_{timestamp}"  # This is where aggregated results are saved

def check_commands():
    commands = ["gitleaks", "git", "trufflehog"]
    for command in commands:
        if shutil.which(command) is None:
            print(f"Error: {command} is not accessible. Please ensure it is installed and available on your system's PATH.")
            sys.exit(1)

    # error if TOKEN is not set
    if TOKEN is None:
        print("Error: GITHUB_ACCESS_TOKEN environment variable not set")
        exit(1)

check_commands()

# If the --clean argument is present, delete the code and temp results directories
if args.clean:
    confirm = input("Are you sure you want to delete the directories ./checkouts and ./reports? (y/n): ")
    if confirm.lower() == "y":
        if DRY_RUN:
            print("Deleting directories ./checkouts and ./reports...")
        else:
            shutil.rmtree(CHECKOUT_DIR, ignore_errors=True)
            shutil.rmtree(GITLEAKS_REPORTS_DIR, ignore_errors=True)
    else:
        print("Operation cancelled.")
    exit(0)

# Function to concatenate CSV files
def concatenate_gitleaks_csv_files(gitleaks_report_filename):
    # Get a list of all CSV files in the {GITLEAKS_REPORTS_DIR} directory
    csv_files = glob.glob(f'{GITLEAKS_REPORTS_DIR}/*.csv')

    # Create a list to hold DataFrames
    df_list = []

    # Loop through the list of CSV files
    for csv_file in csv_files:
        # Check if the CSV file is empty
        if os.stat(csv_file).st_size == 0:
            print(f"Skipping empty file: {csv_file}")
            continue

        # Extract the base name of the file
        base_name = os.path.basename(csv_file)
        # Extract the repository name from the base name. The repo name is the last part of the file name between the last '_' and '.'
        repo_name = base_name.split('_')[-1].split('.')[0]
        
        # get the repo owner name. In the base file name, this is the 3rd token in the file name delimited by '_'
        repo_owner = base_name.split('_')[2]

        # Read the CSV file into a DataFrame
        try:
            df = pd.read_csv(csv_file)
        except pd.errors.ParserError as e:
            print(f"Error reading CSV file: {csv_file}")
            print(e)
            continue
        # Prepend a new column with the repository name
        df.insert(0, 'Owner', repo_owner)
        df.insert(1, 'Repository', repo_name)

        if DRY_RUN:
            print(f"Reading {csv_file}...")

        # Read each non-empty CSV file into a DataFrame and append it to the list
        try:
            df_list.append(df)
        except pd.errors.EmptyDataError:
            print(f"Error: Empty CSV file: {csv_file}")

    concatenated_df = pd.DataFrame()

    # Concatenate all the DataFrames in the list
    if df_list and not DRY_RUN:
        concatenated_df = pd.concat(df_list, ignore_index=True)

    # Check if concatenated_df is empty
    if concatenated_df.empty:
        print(f"WARNING: No results to write to {gitleaks_report_filename}")
    else:
        # Write the concatenated DataFrame to a new CSV file
        print(f"Writing concatenated CSV file to ./{gitleaks_report_filename}...")
        if not DRY_RUN:
            concatenated_df.to_csv(f"{gitleaks_report_filename}", index=False)

def fetch_repos(account_type, account, headers, page=1, per_page=100):
    repos = []
    while True:
        repos_url = f'https://api.github.com/{account_type}/{account}/repos?page={page}&per_page={per_page}'
        if DRY_RUN:
            print(f"Calling {repos_url}...")
        response = requests.get(repos_url, headers=headers)
        data = response.json()
        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return repos

def do_gitleaks_scan(target, repo_name, repo_path):
    # Run gitleaks in each repository. See https://github.com/gitleaks/gitleaks?tab=readme-ov-file#usage
    print(f"Running gitleaks on {repo_path}...")
    command = [
        "gitleaks",
        "detect",
        "-f", # --report-format string
        "csv",
        "-r", # --report-path string
        f"{GITLEAKS_REPORTS_DIR}/gitleaks_findings_{target}_{repo_name}.csv",
        "--source",
        f"{repo_path}",
        "-c", # --config string
        "./.gitleaks.toml", 
        "-v"
    ]
    print("gitleaks command:", " ".join(command))
    if not DRY_RUN:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        print(result.stdout)
        print(result.stderr)

        if result.returncode != 0:
            print(f"Error: gitleaks command returned non-zero exit status {result.returncode}")

# target is the owner of the repository
# repo_name is the name of the repository
# repo_path is the path, relative to this script, to the repository
# Calling trufflehog: tuffflehog filesystem {repo_path} --json
def do_trufflehog_scan(target, repo_name, repo_path, report_filename):
    command = f"trufflehog filesystem {repo_path} --json"
    if DRY_RUN:
        print(f"Running truffleog on owner/repo: {target}/{repo_name}, with command: {command}")
        return
    
    result = subprocess.run(["trufflehog", "filesystem", repo_path, "--json"], capture_output=True, text=True)
    findings = result.stdout.splitlines()
    with open(report_filename, 'a', newline='') as f:
        writer = csv.writer(f)
        for finding in findings:
            json_finding = json.loads(finding)
            if 'SourceMetadata' in json_finding:
                data = json_finding['SourceMetadata']['Data']['Filesystem']
                if 'file' in data:
                    line = data['line'] if 'line' in data else '0' # use 0 if line is not present
                    extra_data = json_finding.get('ExtraData', {})
                    extra_data_values = list(extra_data.values()) if extra_data is not None else []
                    row = [target, repo_name, data['file'], line, json_finding['SourceID'], json_finding['SourceType'], json_finding['SourceName'], json_finding['DetectorType'], json_finding['DetectorName'], json_finding['DecoderName'], json_finding['Verified'], json_finding['Raw'], json_finding['RawV2'], json_finding['Redacted']] + extra_data_values
                    writer.writerow(row)
                else:
                    print(f"Unexpected structure in finding: {finding}")

def analyze_merged_results(merged_results):
    df = pd.read_csv(merged_results)

    # Get the distinct owner values
    distinct_owners = df['owner'].nunique()
    print(f"Owners: {distinct_owners}")

    # Get the distinct source values
    distinct_sources = df['source'].nunique()
    print(f"Scanning Source Tools: {distinct_sources}")

    # Total repos checked out on disk  
    total_repos = count_top_level_dirs(CHECKOUT_DIR)
    print(f"Total Repos on Disk: {total_repos}")

    # Count the total distinct repo_name
    total_repos = df['repo_name'].nunique()
    print(f"Total Repos with Secrets: {total_repos}")

    # Group by source and count total values
    total_secrets_by_source = df.groupby('source')['source'].count().to_dict()
    print(f"Total Secrets by Source: {total_secrets_by_source}")

    # Count the number of total secrets in the secret column
    total_secrets = df['secret'].count()
    print(f"Total Secrets: {total_secrets}")

    # Count the number of total distinct secrets in the secrets column
    total_distinct_secrets = df['secret'].nunique()
    print(f"Total Distinct Secrets: {total_distinct_secrets}")

def clone_repo(repo, repo_checkout_path):
    # Check if the directory already exists
    print(f"Checking if repo {repo_checkout_path} exists or clone if not.")
    if os.path.exists(repo_checkout_path):
        print(f"Repository {repo_checkout_path} already exists. Skipping cloning.")
    else:
        print(f"git clone {repo['clone_url']} {repo_checkout_path}")
        if not DRY_RUN:
            subprocess.run(["git", "clone", repo["clone_url"], f"{repo_checkout_path}"], check=True)

def count_top_level_dirs(directory):
    return len([name for name in os.listdir(directory) if os.path.isdir(os.path.join(directory, name))])

checkout_dir = "./checkout"
print(f"Number of top-level directories in {checkout_dir}: {count_top_level_dirs(checkout_dir)}")

# make reporting directories if they doesn't exist
if not os.path.exists(GITLEAKS_REPORTS_DIR):
    os.makedirs(GITLEAKS_REPORTS_DIR)
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

headers = {"Authorization": f"token {TOKEN}"}

# Column headers for trufflehog report
column_headers = ['target', 'repo_name', 'file', 'line', 'source_id', 'source_type', 'source_name', 'detector_type', 'detector_name', 'decoder_name', 'verified', 'raw', 'raw_v2', 'redacted']
trufflehog_report_filename = f'{REPORTS_DIR}/trufflehog_results_{timestamp}.csv'
with open(trufflehog_report_filename, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(column_headers)


for target in TARGETS:
    # Get list of repositories for the TARGET
    url = f"https://api.github.com/{ORG_TYPE}/{target}/repos"
    print(f"Getting list of repositories from {url}...")
    repos = fetch_repos(ORG_TYPE, target, headers)

    # Check if the response contains an error message
    if "message" in repos and repos["message"] == "Not Found":
        print("Error: Repos not found for owner (target). Double-check the TARGETS.")
    else:
        # Clone each repository
        for repo in repos:
            repo_checkout_path = os.path.join(CHECKOUT_DIR, os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", ""))
            repo_bare_name = os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", "")

            clone_repo(repo, repo_checkout_path)

            do_gitleaks_scan(target, repo_bare_name, repo_checkout_path)
            
            do_trufflehog_scan(target, repo_bare_name, repo_checkout_path, trufflehog_report_filename)
            
# Concatenate all CSV files into a single CSV file
print("Concatenating gitleaks report CSV files...")
gitleaks_merged_report_filename = f"{REPORTS_DIR}/gitleaks_report_merged_filename_{timestamp}.csv"
concatenate_gitleaks_csv_files(gitleaks_merged_report_filename)

ghas_secret_alerts_filename = f"{REPORTS_DIR}/ghas_secret_alerts_{timestamp}.csv"
fetch_ghas_secret_scanning_alerts(ORG_TYPE, TARGETS, headers, ghas_secret_alerts_filename)

print("Secrets scanning execution completed.")
print("Creating merge and match reports.")

# Create a unified reports of all secrets 
merged_report_name = f"{REPORTS_DIR}/merged_scan_results_report_{timestamp}.csv"
unify_csv_files(trufflehog_report_filename, 
                gitleaks_merged_report_filename,  
                ghas_secret_alerts_filename, 
                merged_report_name)

# Create another report that is a subset of the merged report, 
# with only fuzzy matches found among the secrets results   
find_matches(merged_report_name, f"{REPORTS_DIR}/scanning_tool_matches_only.csv")

# Aggregate report results
analyze_merged_results(merged_report_name)
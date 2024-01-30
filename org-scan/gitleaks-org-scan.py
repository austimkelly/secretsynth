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
from logger import *

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--clean", action="store_true", help="delete the directories ./checkouts and ./reports. When --clean is present all other commands are ignored.")
parser.add_argument("--dry-run", action="store_true", help="run the script in dry run mode, don't execute any commands")
parser.add_argument("--keep-secrets-in-reports", action="store_true",
                    help="Keep plain text secrets in the aggregated reports.")
parser.add_argument("--repos-internal-type", action="store_true", help="If your repositories are internal, this flag will be added when fetching repositories from Github.")
parser.add_argument("--org-type", choices=["users", "orgs"], help="set the organization type")
parser.add_argument("--owners", type=str, help="comma-delimited list of owners")

args = parser.parse_args()

# If --clean is not used, --org-type and --owners are required
if not args.clean and (args.org_type is None or args.owners is None):
    parser.error("--org-type and --owners are required unless --clean is used")

DRY_RUN = args.dry_run  # Set to True if --dry-run is present, False otherwise
print(f"DRY_RUN={DRY_RUN}")

KEEP_SECRETS = args.keep_secrets_in_reports
INTERNAL_REPOS_FLAG=args.repos_internal_type
ORG_TYPE = args.org_type if args.org_type else None # This can be "users" or "orgs"
OWNERS = args.owners.split(",") if args.owners else None  # Split the value of --owners into a list if present, None otherwise
TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')
CHECKOUT_DIR = "./checkout"  # This is the directory where the repositories will be cloned
GITLEAKS_REPORTS_DIR = "./gitleaks_reports"  # This is the directory where the gitleaks reports (per repo) will be saved

timestamp = datetime.now().strftime('%Y%m%d%H%M')
REPORTS_DIR = f"./reports/reports_{timestamp}"  # This is where aggregated results are saved
ERROR_LOG_FILE = f"./reports/reports_{timestamp}/error_log_{timestamp}.log"  # This is where error messages are saved
checkout_dir = "./checkout"
headers = {"Authorization": f"token {TOKEN}"}

def check_commands():
    commands = ["gitleaks", "git", "trufflehog"]
    for command in commands:
        if shutil.which(command) is None:
            print(f"ERROR: {command} is not accessible.")
            LOGGER.error(f"ERROR: {command} is not accessible. Please ensure it is installed and available on your system's PATH.")
            sys.exit(1)

    # error if TOKEN is not set
    if TOKEN is None:
        print("ERROR: GITHUB_ACCESS_TOKEN environment variable not set")
        LOGGER.error("ERROR: GITHUB_ACCESS_TOKEN environment variable not set")
        exit(1)

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
            LOGGER.error(f"Error reading CSV file: {csv_file}")
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
            LOGGER.error(f"Error: Empty CSV file: {csv_file}")

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

def fetch_repos(account_type, account, headers, internal_type=False, page=1, per_page=100):

    repos = []
    while True:
        # Docs: https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#list-organization-repositories
        repos_url = f'https://api.github.com/{account_type}/{account}/repos?page={page}&per_page={per_page}'
        if internal_type:
            repos_url += '&type=internal'
        if DRY_RUN:
            print(f"Calling {repos_url}...")

        response = requests.get(repos_url, headers=headers)
        data = response.json()
        
        if isinstance(data, dict) and "message" in data:
            print(f"ERROR: Error fetching repo list from Github API:  {data['message']}")
            LOGGER.error(f"ERROR: Error fetching repo list from Github API:  {data['message']}")
            break;

        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1

    return repos

def do_gitleaks_scan(target, repo_name, repo_path):
    # Run gitleaks in each repository. See https://github.com/gitleaks/gitleaks?tab=readme-ov-file#usage
    print(f"Running gitleaks on {repo_path} ...")
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
        #"-v"
    ]
    print("gitleaks command:", " ".join(command))
    if not DRY_RUN:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        print(result.stdout)
        #print(result.stderr)

        if result.returncode != 0:
            print(f"gitleaks command returned non-zero exit status {result.returncode}")

# target is the owner of the repository
# repo_name is the name of the repository
# repo_path is the path, relative to this script, to the repository
# Calling trufflehog: tuffflehog filesystem {repo_path} --json
def do_trufflehog_scan(target, repo_name, repo_path, report_filename):
    command = f"trufflehog filesystem {repo_path} --json"
    
    print(f"Running truffleog on owner/repo: {target}/{repo_name}, with command: {command}")
    
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

def analyze_merged_results(merged_results, repo_names_no_ghas_secrets_enabled):
    df = pd.read_csv(merged_results)

    # Calculate the metrics
    cmd_args = sys.argv
    owners = df['owner'].nunique()
    distinct_sources = df['source'].nunique()
    total_repos_on_disk = count_top_level_dirs(CHECKOUT_DIR)
    total_repos_with_secrets = df['repo_name'].nunique()
    total_secrets_by_source = df.groupby('source')['source'].count().to_dict()
    total_secrets = df['secret'].count()
    repos_without_ghas_secrets_scanning = len(repo_names_no_ghas_secrets_enabled) if repo_names_no_ghas_secrets_enabled else 0
    total_distinct_secrets = df['secret'].nunique()

    # Create a DataFrame with the metrics
    metrics = pd.DataFrame({
        'Metric': ['Arguments', 'Owners', 'Scanning Source Tools', 'Total Repos on Disk', 'Total Repos with Secrets', 'Total Secrets by Source', 'Total Secrets', 'Repos without GHAS Secrets Scanning Enabled', 'Total Distinct Secrets'],
        'Value': [cmd_args, owners, distinct_sources, total_repos_on_disk, total_repos_with_secrets, total_secrets_by_source, total_secrets, repos_without_ghas_secrets_scanning, total_distinct_secrets]
    })

    return metrics

def output_to_html(metrics, 
                   merged_report_name, 
                   ghas_secret_alerts_filename, 
                   matches_report_name,
                   error_logfile, 
                   report_path 
                   ):
    # Create a DataFrame with links to the raw report files
    report_links = pd.DataFrame({
        'Report Name': ['Merged Report', 'GHAS Secret Alerts', 'Matches Report', "Error Log"],
        'CSV Link': [f'<a href="{merged_report_name}">{merged_report_name}</a>',
                     f'<a href="{ghas_secret_alerts_filename}">{ghas_secret_alerts_filename}</a>',
                     f'<a href="{matches_report_name}">{matches_report_name}</a>',
                     f'<a href="{error_logfile}">{error_logfile}</a>']
    })

    # Convert the DataFrames to HTML
    metrics_html = metrics.to_html()
    report_links_html = report_links.to_html(escape=False)

    # Write the HTML to a file
    with open(report_path, 'w') as f:
        f.write('<h1>Metrics</h1>')
        f.write(metrics_html)
        f.write('<h1>Report Links</h1>')
        f.write(report_links_html)

    # Print the absolute path of the HTML file
    print(f"HTML file written to: {report_path}")

def clone_repo(repo, repo_checkout_path):
    # Check if the directory already exists
    #print(f"Checking if repo {repo_checkout_path} exists or clone if not.")
    if os.path.exists(repo_checkout_path):
        print(f"Repository {repo_checkout_path} already exists. Skipping cloning.")
    else:
        print(f"git clone {repo['clone_url']} {repo_checkout_path}")
        if not DRY_RUN:
            subprocess.run(["git", "clone", repo["clone_url"], f"{repo_checkout_path}"], check=True)

def count_top_level_dirs(directory):
    return len([name for name in os.listdir(directory) if os.path.isdir(os.path.join(directory, name))])

# make reporting directories if they doesn't exist
if not os.path.exists(GITLEAKS_REPORTS_DIR):
    os.makedirs(GITLEAKS_REPORTS_DIR)
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

LOGGER = setup_error_logger(ERROR_LOG_FILE)
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

# Column headers for trufflehog report
column_headers = ['target', 'repo_name', 'file', 'line', 'source_id', 'source_type', 'source_name', 'detector_type', 'detector_name', 'decoder_name', 'verified', 'raw', 'raw_v2', 'redacted']
trufflehog_report_filename = f'{REPORTS_DIR}/trufflehog_results_{timestamp}.csv'
with open(trufflehog_report_filename, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(column_headers)

for owner in OWNERS: 
    # Get list of repositories for the TARGET
    url = f"https://api.github.com/{ORG_TYPE}/{owner}/repos"
    print(f"Getting list of repositories from {url}...")
    
    repos = fetch_repos(ORG_TYPE, owner, headers, INTERNAL_REPOS_FLAG,)
    
    # Check if the response is a dictionary containing an error message
    if isinstance(repos, dict) and "message" in repos:
        print(f"ERROR: Error on owner: {owner} with message:  {repos['message']}")
        LOGGER.error(f"ERROR: Error on owner: {owner} with message:  {repos['message']}")
        break;
    elif repos is None or len(repos) == 0:
        print(f"ERROR: No repositories found for {owner}. Please check your Github personal access token and that you have the correct permission to read from the org: {owner}")
        LOGGER.error(f"ERROR: No repositories found for {owner}. Please check your Github personal access token and that you have the correct permission to read from the org: {owner}")
        continue;
    else:
        # Clone each repository and do a basic gitleaks and trufflehog scan
        for repo in repos:
            repo_checkout_path = os.path.join(CHECKOUT_DIR, os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", ""))
            repo_bare_name = os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", "")

            clone_repo(repo, repo_checkout_path)

            do_gitleaks_scan(owner, repo_bare_name, repo_checkout_path)
            
            do_trufflehog_scan(owner, repo_bare_name, repo_checkout_path, trufflehog_report_filename)
            
# Concatenate all CSV files into a single CSV file
if not os.path.exists(CHECKOUT_DIR):    # Skip if ./checkout does not exist
    print("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")
    LOGGER.error("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")  
    exit(1)

print("Concatenating gitleaks report CSV files...")
gitleaks_merged_report_filename = f"{REPORTS_DIR}/gitleaks_report_merged_filename_{timestamp}.csv"
concatenate_gitleaks_csv_files(gitleaks_merged_report_filename)

ghas_secret_alerts_filename = f"{REPORTS_DIR}/ghas_secret_alerts_{timestamp}.csv"
repos_without_ghas_secrets_enabled = fetch_ghas_secret_scanning_alerts(ORG_TYPE, OWNERS, headers, ghas_secret_alerts_filename, LOGGER)
print("Secrets scanning execution completed.")

print("Creating merge and match reports.")

# Create a unified reports of all secrets 
merged_report_name = f"{REPORTS_DIR}/merged_scan_results_report_{timestamp}.csv"
merge_csv_all_tools(trufflehog_report_filename, 
                gitleaks_merged_report_filename,  
                ghas_secret_alerts_filename,
                KEEP_SECRETS, 
                merged_report_name)

# Create another report that is a subset of the merged report, 
# with only fuzzy matches found among the secrets results
matches_report_name = f"{REPORTS_DIR}/scanning_tool_matches_only_{timestamp}.csv" 
find_matches(merged_report_name, matches_report_name)

if not KEEP_SECRETS:
    # Delete gitleaks_merged_report_filename & trufflehog_report_filename
    # because these reports contain secrets in plain text
    print(f"Deleting {trufflehog_report_filename} and {gitleaks_merged_report_filename}...")
    os.remove(gitleaks_merged_report_filename)
    os.remove(trufflehog_report_filename)

# Aggregate report results
metrics = analyze_merged_results(merged_report_name, repos_without_ghas_secrets_enabled)
html_report_path = f"{REPORTS_DIR}/report_{timestamp}.html"
output_to_html(metrics, f"../../{merged_report_name}", 
               f"../../{ghas_secret_alerts_filename}", 
               f"../../{matches_report_name}", 
               f"../../{ERROR_LOG_FILE}",
               html_report_path)

#secretsynth.py
# License: MIT License

import os
import requests
import subprocess
import pandas as pd
from urllib.parse import urlparse
import argparse
import shutil
from datetime import datetime
import csv
import sys
import webbrowser
import time

# import all functions our helper modules
# scanners
from scanners.trufflehog_scan import *
from scanners.noseyparker_scan import *
from scanners.gitleaks_scan import *
from scanners.ghas_secret_alerts_fetch import *
# utils
from utils.logger import *
# reporting
from reporting.csv_coalesce import *
from reporting.html_report_writer import *
from reporting.secret_matcher import *

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--clean", action="store_true", help="delete the directories ./checkouts and ./reports. When --clean is present all other commands are ignored.")
parser.add_argument("--dry-run", action="store_true", help="run the script in dry run mode, don't execute any commands")
parser.add_argument("--keep-secrets-in-reports", action="store_true",
                    help="Keep plain text secrets in the aggregated reports. By default the tool will hash secrets for final reports if this flag is missing.")
parser.add_argument("--repos-internal-type", action="store_true", help="If your repositories are internal, this flag will be added when fetching repositories from Github.")
parser.add_argument("--org-type", choices=["users", "orgs"], help="set the organization type")
parser.add_argument("--owners", type=str, help="comma-delimited list of owners")
parser.add_argument("--skip-noseyparker", action="store_true", help="Skip the Noseyparker scan")
parser.add_argument("--skip-trufflehog", action="store_true", help="Skip the TruffleHog scan")
parser.add_argument("--skip-ghas", action="store_true", help="Skip the GitHub Advanced Security alerts scan")
parser.add_argument("--skip-gitleaks", action="store_true", help="Skip the Gitleaks scan")
parser.add_argument("--open-report-in-browser", action="store_true", help="Open the report in a browser after it's generated")

args = parser.parse_args()

SKIP_NOSEYPARKER = args.skip_noseyparker
SKIP_TRUFFLEHOG = args.skip_trufflehog
SKIP_GHAS = args.skip_ghas
SKIP_GITLEAKS = args.skip_gitleaks

# If --clean is not used, --org-type and --owners are required
if not args.clean and (args.org_type is None or args.owners is None):
    parser.error("--org-type and --owners are required unless --clean is used")

DRY_RUN = args.dry_run  # Set to True if --dry-run is present, False otherwise
print(f"DRY_RUN={DRY_RUN}")

print(f"SKIP_NOSEYPARKER={SKIP_NOSEYPARKER}")
print(f"SKIP_TRUFFLEHOG={SKIP_TRUFFLEHOG}")
print(f"SKIP_GHAS={SKIP_GHAS}")
print(f"SKIP_GITLEAKS={SKIP_GITLEAKS}")

timestamp = datetime.now().strftime('%Y%m%d%H%M')
KEEP_SECRETS = args.keep_secrets_in_reports
print(f"KEEP_SECRETS={KEEP_SECRETS}")
INTERNAL_REPOS_FLAG=args.repos_internal_type
ORG_TYPE = args.org_type if args.org_type else None # This can be "users" or "orgs"
OWNERS = args.owners.split(",") if args.owners else None  # Split the value of --owners into a list if present, None otherwise
OPEN_REPORT_IN_BROWSER = args.open_report_in_browser

TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')

# artifact directories
CHECKOUT_DIR = "./_checkout"  # This is the directory where the repositories will be cloned
GITLEAKS_REPORTS_DIR = "./_gitleaks_reports"  # This is the directory where the gitleaks reports (per repo) will be saved
NOSEY_PARKER_ROOT_ARTIFACT_DIR = "./_np_datastore"
NOSEYPARKER_DATASTORE_DIR = f"{NOSEY_PARKER_ROOT_ARTIFACT_DIR}/np_datastore_{timestamp}"
REPORTS_DIR = f"./_reports/reports_{timestamp}"  # This is where aggregated results are saved
ERROR_LOG_FILE = f"./_reports/reports_{timestamp}/error_log_{timestamp}.log"  # This is where error messages are saved

github_rest_headers = {
    "Authorization": f"token {TOKEN}",
    "X-GitHub-Api-Version": "2022-11-28",
    "Accept": "application/vnd.github+json"
}

def check_commands():
    commands = {
        "gitleaks": SKIP_GITLEAKS,
        "trufflehog": SKIP_TRUFFLEHOG,
        "noseyparker": SKIP_NOSEYPARKER
    }
    # On each iteration, command is set to the key and skip is set to the value of the current tuple pair.
    for command, skip in commands.items():
        if not skip and shutil.which(command) is None:
            sys.stderr.write(f"FATAL ERROR: {command} is not accessible. Use one of the --skip flags to skip the scan. Exiting...\n")
            LOGGER.error(f"ERROR: {command} is not accessible. Please ensure it is installed and available on your system's PATH.")
            sys.exit(1)

    # Check for git separately since it cannot be skipped
    if shutil.which("git") is None:
        sys.stderr.write("FATAL ERROR: git is not accessible. Exiting...\n")
        LOGGER.error("ERROR: git is not accessible. Please ensure it is installed and available on your system's PATH.")
        sys.exit(1)

    # error if TOKEN is not set
    if TOKEN is None:
        sys.stderr.write("FATAL ERROR: GITHUB_ACCESS_TOKEN environment variable not set. Exiting...\n")
        LOGGER.error("FATAL ERROR: GITHUB_ACCESS_TOKEN environment variable not set. Exiting...")
        exit(1)


def fetch_repos(account_type, account, github_rest_headers, internal_type=False, page=1, per_page=100):

    repos = []
    while True:
        # Docs: https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#list-organization-repositories
        repos_url = f'https://api.github.com/{account_type}/{account}/repos?page={page}&per_page={per_page}'
        if internal_type:
            repos_url += '&type=internal'
        if DRY_RUN:
            print(f"dry-run: Calling {repos_url}...")
            break;

        response = requests.get(repos_url, headers=github_rest_headers)
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

def count_lines_in_file(file_path):
    _, file_extension = os.path.splitext(file_path)
    if file_extension == '.csv':
        with open(file_path, 'r') as file:
            return sum(1 for row in csv.reader(file))
    else:
        with open(file_path, 'r') as file:
            return sum(1 for line in file)

# Docs for analyze_merged_results
# merged_results: the path to the merged results CSV file
# matches_results: the path to the matches results CSV file
# error_file: the path to the error log file
# repo_names_no_ghas_secrets_enabled: a list of repository names that do not have GHAS secrets scanning enabled
# Returns: a tuple of two DataFrames: the first is the metrics DataFrame, the second is the repo-level metrics DataFrame
def analyze_merged_results(merged_results, 
                           matches_results, 
                           error_file, 
                           repo_names_no_ghas_secrets_enabled=None):
    
    df = pd.read_csv(merged_results)

    # check if merged_results is empty or only has one line (header row). If true, return empty DataFrames
    if df.empty or len(df) == 1:
        LOGGER.error(f"ERROR: The merged results file {merged_results} is empty or only has one line (header row). No metrics will be generated.")
        print(f"ERROR: The merged results file {merged_results} is empty or only has one line (header row). No metrics will be generated.")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    
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
    now = datetime.now()
    err_line_count = count_lines_in_file(error_file)
    matches_line_count = count_lines_in_file(matches_results) - 1 # subtract 1 for the header row

    # Create a DataFrame with the metrics
    metrics = pd.DataFrame({
        'Metric': ['Time of Report', 'Arguments', 'Owners', 'Scanning Source Tools', 'Total Repos on Disk', 'Total Repos with Secrets', 'Total Secrets by Source', 'Total Secrets (all tools)', 'Repos with GHAS Secrets Scanning Disabled', 'Total Distinct Secrets', 'Secret Matches Count (Experimental)', 'Total Errors in Log'],
        'Value': [now, cmd_args, owners, distinct_sources, total_repos_on_disk, total_repos_with_secrets, total_secrets_by_source, total_secrets, repos_without_ghas_secrets_scanning, total_distinct_secrets, matches_line_count, err_line_count]
    })

    # Do repo-level metrics
    # Rows will be 'repos'
    # columns wil be: total secrets, total distinct secrets, 
    # total gitleaks secrets, total trufflehog secrets, total noseyparker secrets, total ghas secrets
    grouped = df.groupby('repo_name')

    repo_metrics = grouped.agg({
        'secret': ['count', 'nunique'],
        'source': [
            ('total_gitleaks_secrets', lambda x: (x == 'gitleaks').sum()),
            ('total_trufflehog_secrets', lambda x: (x == 'trufflehog').sum()),
            ('total_noseyparker_secrets', lambda x: (x == 'noseyparker').sum()),
            ('total_ghas_secrets', lambda x: (x == 'ghas').sum())
        ]
    })

    # Add a summary row
    repo_metrics.loc['Summary', :] = repo_metrics.sum(numeric_only=True)
    # Convert the entire table integers. Doing a summary converts everything to floats
    repo_metrics = repo_metrics.astype(int)

    # Reset the index
    repo_metrics.reset_index(inplace=True)

    # Flatten the multi-index columns
    repo_metrics.columns = ['_'.join(col).strip() for col in repo_metrics.columns.values]

    # analyze the detector in a new table
    # Group by 'detector' and count the number of rows for each detector
    detector_metrics = df.groupby(['source', 'detector']).size().reset_index(name='detector_count')
    # Order by 'detector_count' in descending order
    detector_metrics = detector_metrics.sort_values('detector_count', ascending=False)
    # Remove the index
    detector_metrics.reset_index(drop=True, inplace=True)
    # Write the detector metrics to a temporary CSV file
    #detector_metrics.to_csv('temp_detector_metrics.csv')

    return metrics, repo_metrics, detector_metrics

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

# If the --clean argument is present, delete the code and temp results directories
if args.clean:
    confirm = input("Are you sure you want to delete the directories ./checkouts and ./reports? (y/n): ")
    if confirm.lower() == "y":
        if DRY_RUN:
            print(f"dry-run: Deleting directories {CHECKOUT_DIR}, {GITLEAKS_REPORTS_DIR} and {NOSEY_PARKER_ROOT_ARTIFACT_DIR}...")
        else:
            shutil.rmtree(CHECKOUT_DIR, ignore_errors=True)
            shutil.rmtree(GITLEAKS_REPORTS_DIR, ignore_errors=True)
            shutil.rmtree(NOSEY_PARKER_ROOT_ARTIFACT_DIR, ignore_errors=True)
    else:
        print("Operation cancelled. No clean up was performed. Exiting...")

    exit(0)

# make reporting directories if they doesn't exist
if not DRY_RUN:
    if not os.path.exists(GITLEAKS_REPORTS_DIR):
        os.makedirs(GITLEAKS_REPORTS_DIR)
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    LOGGER = setup_error_logger(ERROR_LOG_FILE)
else:
    LOGGER = None

if not DRY_RUN:   
    check_commands()

trufflehog_report_filename = f'{REPORTS_DIR}/trufflehog_results_{timestamp}.csv'
noseyparker_report_filename = f"{REPORTS_DIR}/noseyparker_results_{timestamp}.csv" 

if not DRY_RUN:
# Column headers for trufflehog report
    trufflehog_column_headers = ['target', 'repo_name', 'file', 'line', 'source_id', 'source_type', 'source_name', 'detector_type', 'detector_name', 'decoder_name', 'verified', 'raw', 'raw_v2', 'redacted']
    with open(trufflehog_report_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(trufflehog_column_headers)

    with open(noseyparker_report_filename, 'w', newline='') as f:
        writer = csv.writer(f)   

    if not os.path.exists(NOSEYPARKER_DATASTORE_DIR):
        os.makedirs(NOSEYPARKER_DATASTORE_DIR)

# Initialize counters for time spent on each secrets scanning tool
timing_metrics = {
    "total_gitleaks_time": 0,
    "total_trufflehog_time": 0,
    "total_noseyparker_time": 0
}

for owner in OWNERS: 
    # Get list of repositories for the TARGET
    url = f"https://api.github.com/{ORG_TYPE}/{owner}/repos"
    print(f"Getting list of repositories from {url}...")
    
    repos = fetch_repos(ORG_TYPE, owner, github_rest_headers, INTERNAL_REPOS_FLAG,)
    
    # Check if the response is a dictionary containing an error message
    if isinstance(repos, dict) and "message" in repos:
        print(f"ERROR: Error on owner: {owner} with message:  {repos['message']}")
        if LOGGER:
            LOGGER.error(f"ERROR: Error on owner: {owner} with message:  {repos['message']}")
        break;
    elif repos is None or len(repos) == 0:
        if not DRY_RUN:
            print(f"ERROR: No repositories found for {owner}. Please check your Github personal access token and that you have the correct permission to read from the org: {owner}")
            if LOGGER:
                LOGGER.error(f"ERROR: No repositories found for {owner}. Please check your Github personal access token and that you have the correct permission to read from the org: {owner}")
            continue;
    else:
        # Clone each repository and do a basic gitleaks and trufflehog scan
        for repo in repos:
            repo_checkout_path = os.path.join(CHECKOUT_DIR, os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", ""))
            repo_bare_name = os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", "")

            clone_repo(repo, repo_checkout_path)

            if not SKIP_GITLEAKS:
                start_time = time.time()
                do_gitleaks_scan(owner, repo_bare_name, repo_checkout_path, GITLEAKS_REPORTS_DIR, DRY_RUN, LOGGER)
                end_time = time.time()
                timing_metrics["total_gitleaks_time"] += end_time - start_time

            if not SKIP_TRUFFLEHOG:
                start_time = time.time()
                do_trufflehog_scan(owner, repo_bare_name, repo_checkout_path, trufflehog_report_filename, DRY_RUN, LOGGER)
                end_time = time.time()
                timing_metrics["total_trufflehog_time"] += end_time - start_time

            if not SKIP_NOSEYPARKER:
                start_time = time.time()
                do_noseyparker_scan(owner, repo_bare_name, repo_checkout_path, NOSEYPARKER_DATASTORE_DIR, DRY_RUN, LOGGER)
                end_time = time.time()
                timing_metrics["total_noseyparker_time"] += end_time - start_time

    if not SKIP_NOSEYPARKER and not DRY_RUN:
        run_noseyparker_report(owner, NOSEYPARKER_DATASTORE_DIR, noseyparker_report_filename, LOGGER)

# Calculate total time
if not DRY_RUN:
    total_time = sum(timing_metrics.values())
    for function, time_spent in timing_metrics.items():
        if total_time != 0:
            percentage = (time_spent / total_time) * 100
            print(f"Total {function}: {time_spent:.2f} seconds ({percentage:.2f}%)")
        else:
            print(f"Total {function}: {time_spent:.2f} seconds (0.00%)")
    if total_time != 0:
        print(f"Total time: {total_time:.2f} seconds")
    else:
        print("Total time: 0.00 seconds")

# Concatenate all CSV files into a single CSV file
if not os.path.exists(CHECKOUT_DIR) and not DRY_RUN:    # Skip if ./checkout does not exist
    print("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")
    LOGGER.error("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")  
    exit(0)

gitleaks_merged_report_filename = f"{REPORTS_DIR}/gitleaks_report_merged_filename_{timestamp}.csv"
if not SKIP_GITLEAKS:
    print("Concatenating gitleaks report CSV files...")
    if not DRY_RUN:
        concatenate_gitleaks_csv_files(gitleaks_merged_report_filename, GITLEAKS_REPORTS_DIR, LOGGER)

ghas_secret_alerts_filename = f"{REPORTS_DIR}/ghas_secret_alerts_{timestamp}.csv"
if not SKIP_GHAS:
    repos_without_ghas_secrets_enabled = fetch_ghas_secret_scanning_alerts(ORG_TYPE, OWNERS, github_rest_headers, ghas_secret_alerts_filename, DRY_RUN, LOGGER)
else:
    repos_without_ghas_secrets_enabled = None
        
print("Secrets scanning execution completed.")
print("Creating merge and match reports.")

if not DRY_RUN:
    # Create a unified reports of all secrets 
    merged_report_name = f"{REPORTS_DIR}/merged_scan_results_report_{timestamp}.csv"
    merge_csv_all_tools(KEEP_SECRETS, trufflehog_report_filename, 
                    gitleaks_merged_report_filename,  
                    ghas_secret_alerts_filename,
                    noseyparker_report_filename, 
                    merged_report_name, LOGGER)

    # Create another report that is a subset of the merged report, 
    # with only fuzzy matches found among the secrets results
    matches_report_name = f"{REPORTS_DIR}/scanning_tool_matches_only_{timestamp}.csv" 
    find_matches(merged_report_name, matches_report_name, 90)

    if not KEEP_SECRETS:
        # Delete gitleaks_merged_report_filename & trufflehog_report_filename
        # because these reports contain secrets in plain text
        print(f"Deleting (if exist) {trufflehog_report_filename}, {gitleaks_merged_report_filename}, and {noseyparker_report_filename}...")
        if os.path.isfile(gitleaks_merged_report_filename):
            os.remove(gitleaks_merged_report_filename)
        if os.path.isfile(trufflehog_report_filename):
            os.remove(trufflehog_report_filename)
        if os.path.isfile(noseyparker_report_filename):
            os.remove(noseyparker_report_filename)
        if os.path.isfile(ghas_secret_alerts_filename):
            os.remove(ghas_secret_alerts_filename)

    # Aggregate report results
    metrics, repo_metrics, detector_metrics = analyze_merged_results(merged_report_name, matches_report_name, ERROR_LOG_FILE, repos_without_ghas_secrets_enabled)
    html_report_path = f"{REPORTS_DIR}/report_{timestamp}.html"
    output_to_html(metrics, repo_metrics, detector_metrics, timing_metrics, 
                f"../../{merged_report_name}", 
                f"../../{ghas_secret_alerts_filename}", 
                f"../../{matches_report_name}", 
                f"../../{ERROR_LOG_FILE}",
                html_report_path)
    
    if OPEN_REPORT_IN_BROWSER:
        # open the report in the default browser
        absolute_path = os.path.abspath(html_report_path)
        webbrowser.open(f"file://{absolute_path}", new=2)

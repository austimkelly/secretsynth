#secretsynth.py
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
import sys
import webbrowser

# import all functions our helper modules
from csv_coalesce import *
from ghas_secret_alerts_fetch import *
from logger import *
from trufflehog_scan import *
from noseyparker_scan import *
from gitleaks_scan import *
from html_report_writer import *
from secret_matcher import *

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
CHECKOUT_DIR = "./checkout"  # This is the directory where the repositories will be cloned
GITLEAKS_REPORTS_DIR = "./gitleaks_reports"  # This is the directory where the gitleaks reports (per repo) will be saved
NOSEY_PARKER_ROOT_ARTIFACT_DIR = "./np_datastore"
NOSEYPARKER_DATASTORE_DIR = f"{NOSEY_PARKER_ROOT_ARTIFACT_DIR}/np_datastore_{timestamp}"
REPORTS_DIR = f"./reports/reports_{timestamp}"  # This is where aggregated results are saved
ERROR_LOG_FILE = f"./reports/reports_{timestamp}/error_log_{timestamp}.log"  # This is where error messages are saved
checkout_dir = "./checkout"
headers = {"Authorization": f"token {TOKEN}"}

def check_commands():
    commands = ["gitleaks", "git", "trufflehog", "noseyparker"]
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
            print(f"dry-run: Reading {csv_file}...")

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
            print(f"dry-run: Calling {repos_url}...")
            break;

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
def analyze_merged_results(merged_results, matches_results, error_file, repo_names_no_ghas_secrets_enabled=None):
    
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
    now = datetime.now()
    err_line_count = count_lines_in_file(error_file)
    matches_line_count = count_lines_in_file(matches_results) - 1 # subtract 1 for the header row

    # Create a DataFrame with the metrics
    metrics = pd.DataFrame({
        'Metric': ['Time of Report', 'Arguments', 'Owners', 'Scanning Source Tools', 'Total Repos on Disk', 'Total Repos with Secrets', 'Total Secrets by Source', 'Total Secrets (all tools)', 'Repos without GHAS Secrets Scanning Enabled', 'Total Distinct Secrets', 'Secret Matches Count (Experimental)', 'Total Errors in Log'],
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
    detector_metrics = df.groupby('detector').size().reset_index(name='detector_count')
    # Order by 'detector_count' in descending order
    detector_metrics = detector_metrics.sort_values('detector_count', ascending=False)
    # Remove the index
    detector_metrics.reset_index(drop=True, inplace=True)
    # Write the detector metrics to a temporary CSV file
    detector_metrics.to_csv('temp_detector_metrics.csv')

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
            print("dry-run: Deleting directories ./checkouts and ./reports...")
        else:
            shutil.rmtree(CHECKOUT_DIR, ignore_errors=True)
            shutil.rmtree(GITLEAKS_REPORTS_DIR, ignore_errors=True)
            shutil.rmtree(NOSEY_PARKER_ROOT_ARTIFACT_DIR, ignore_errors=True)
    else:
        print("Operation cancelled.")
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

for owner in OWNERS: 
    # Get list of repositories for the TARGET
    url = f"https://api.github.com/{ORG_TYPE}/{owner}/repos"
    print(f"Getting list of repositories from {url}...")
    
    repos = fetch_repos(ORG_TYPE, owner, headers, INTERNAL_REPOS_FLAG,)
    
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
                do_gitleaks_scan(owner, repo_bare_name, repo_checkout_path, GITLEAKS_REPORTS_DIR, DRY_RUN, LOGGER)

            if not SKIP_TRUFFLEHOG:        
                do_trufflehog_scan(owner, repo_bare_name, repo_checkout_path, trufflehog_report_filename, DRY_RUN, LOGGER)

            if not SKIP_NOSEYPARKER:
                do_noseyparker_scan(owner, repo_bare_name, repo_checkout_path, NOSEYPARKER_DATASTORE_DIR, DRY_RUN, LOGGER)

    if not SKIP_NOSEYPARKER and not DRY_RUN:
        run_noseyparker_report(owner, NOSEYPARKER_DATASTORE_DIR, noseyparker_report_filename, LOGGER)

# Concatenate all CSV files into a single CSV file
if not os.path.exists(CHECKOUT_DIR) and not DRY_RUN:    # Skip if ./checkout does not exist
    print("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")
    LOGGER.error("ERROR: The ./checkout folder does not exist. Check your git configuration and try again. No reports will be generated.")  
    exit(1)

gitleaks_merged_report_filename = f"{REPORTS_DIR}/gitleaks_report_merged_filename_{timestamp}.csv"
if not SKIP_GITLEAKS:
    print("Concatenating gitleaks report CSV files...")
    concatenate_gitleaks_csv_files(gitleaks_merged_report_filename)

ghas_secret_alerts_filename = f"{REPORTS_DIR}/ghas_secret_alerts_{timestamp}.csv"
if not SKIP_GHAS:
    repos_without_ghas_secrets_enabled = fetch_ghas_secret_scanning_alerts(ORG_TYPE, OWNERS, headers, ghas_secret_alerts_filename, DRY_RUN, LOGGER)
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
    find_matches(merged_report_name, matches_report_name)

    if not KEEP_SECRETS:
        # Delete gitleaks_merged_report_filename & trufflehog_report_filename
        # because these reports contain secrets in plain text
        print(f"Deleting {trufflehog_report_filename}, {gitleaks_merged_report_filename}, and {noseyparker_report_filename}...")
        os.remove(gitleaks_merged_report_filename)
        os.remove(trufflehog_report_filename)
        os.remove(noseyparker_report_filename)

    # Aggregate report results
    metrics, repo_metrics, detector_metrics = analyze_merged_results(merged_report_name, matches_report_name, ERROR_LOG_FILE, repos_without_ghas_secrets_enabled)
    html_report_path = f"{REPORTS_DIR}/report_{timestamp}.html"
    output_to_html(metrics, repo_metrics, detector_metrics,
                f"../../{merged_report_name}", 
                f"../../{ghas_secret_alerts_filename}", 
                f"../../{matches_report_name}", 
                f"../../{ERROR_LOG_FILE}",
                html_report_path)
    
    if OPEN_REPORT_IN_BROWSER:
        # open the report in the default browser
        absolute_path = os.path.abspath(html_report_path)
        webbrowser.open(f"file://{absolute_path}", new=2)

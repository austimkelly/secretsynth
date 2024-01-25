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

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--clean", action="store_true", help="delete the directories ./checkouts and ./reports")
args = parser.parse_args()

ORG_TYPE = "users"  # This can be either "users" or "orgs"
TARGETS = ["austimkelly"]  # This can be a username or an org name
TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')
CHECKOUT_DIR = "./checkout"  # This is the directory where the repositories will be cloned
REPORTS_DIR = "./reports"  # This is the directory where the gitleaks reports will be saved

# error if TOKEN is not set
if TOKEN is None:
    print("Error: GITHUB_ACCESS_TOKEN environment variable not set")
    exit(1)

DRY_RUN = False  # Set to False to actually execute commands
print(f"DRY_RUN={DRY_RUN}")

# If the --clean argument is present, delete the directories
if args.clean:
    confirm = input("Are you sure you want to delete the directories ./checkouts and ./reports? (y/n): ")
    if confirm.lower() == "y":
        shutil.rmtree(CHECKOUT_DIR, ignore_errors=True)
        shutil.rmtree(REPORTS_DIR, ignore_errors=True)
    else:
        print("Operation cancelled.")
    exit(0)

# Function to concatenate CSV files
def concatenate_csv_files():
    # Get a list of all CSV files in the {REPORTS_DIR} directory
    csv_files = glob.glob(f'{REPORTS_DIR}/*.csv')

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
        #repo_name = base_name.replace('gitleaks_findings_
        
        # get the repo owner name. In the base file name, this is the 3rd token in the file name delimited by '_'
        repo_owner = base_name.split('_')[2]

        # Read the CSV file into a DataFrame
        df = pd.read_csv(csv_file)
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
        print("WARNING: No results to write to report_concat.csv")
    else:
        # Write the concatenated DataFrame to a new CSV file
        print(f"Writing concatenated CSV file to {REPORTS_DIR}/report_concat.csv...")
        if not DRY_RUN:
            concatenated_df.to_csv('report_concat.csv', index=False)

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

# make ./reports directory if it doesn't exist
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

# Get list of repositories for the TARGET

headers = {"Authorization": f"token {TOKEN}"}
for target in TARGETS:
    url = f"https://api.github.com/{ORG_TYPE}/{target}/repos"
    print(f"Getting list of repositories from {url}...")
    repos = fetch_repos(ORG_TYPE, target, headers)

    # Check if the response contains an error message
    if "message" in repos and repos["message"] == "Not Found":
        print("Error: Repos not found for owner (target). Double-check the TARGETS.")
    else:
        # Clone each repository
        for repo in repos:
            repo_name = os.path.join(CHECKOUT_DIR, os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", ""))
            repo_bare_name = os.path.basename(urlparse(repo["clone_url"]).path).replace(".git", "")

            # Check if the directory already exists
            print(f"Checking if repo {repo_name} exists or clone if not.")
            if os.path.exists(repo_name):
                print(f"Repository {repo_name} already exists. Skipping cloning.")
            else:
                print(f"git clone {repo['clone_url']} {repo_name}")
                if not DRY_RUN:
                    subprocess.run(["git", "clone", repo["clone_url"], f"{repo_name}"], check=True)

            # Run gitleaks in each repository. See https://github.com/gitleaks/gitleaks?tab=readme-ov-file#usage
            print(f"Running gitleaks on {repo_name}...")
            command = [
                "gitleaks",
                "detect",
                "-f", # --report-format string
                "csv",
                "-r", # --report-path string
                f"./reports/gitleaks_findings_{target}_{repo_bare_name}.csv",
                "--source",
                f"{repo_name}",
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

# Concatenate all CSV files into a single CSV file
print("Concatenating CSV files...")
concatenate_csv_files()

print("Script execution completed.")

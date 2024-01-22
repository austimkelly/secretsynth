#gitleaks-org-scan.py
# License: MIT License

import os
import requests
import subprocess
import glob
import pandas as pd
from urllib.parse import urlparse

ORG_TYPE = "users"  # This can be either "users" or "orgs"
TARGET = "austimkelly"  # This can be a username or an org name
TOKEN = os.getenv('GITHUB_ACCESS_TOKEN')
CHECKOUT_DIR = "./checkout"  # This is the directory where the repositories will be cloned
REPORTS_DIR = "./reports"  # This is the directory where the gitleaks reports will be saved

# error if TOKEN is not set
if TOKEN is None:
    print("Error: GITHUB_ACCESS_TOKEN environment variable not set")
    exit(1)

DRY_RUN = False  # Set to False to actually execute commands
print(f"DRY_RUN={DRY_RUN}")

# Function to concatenate CSV files
def concatenate_csv_files():
    # Get a list of all CSV files in the {REPORTS_DIR} directory
    csv_files = glob.glob(f'{REPORTS_DIR}/*.csv')

    # Create a list to hold DataFrames
    df_list = []

    # Loop through the list of CSV files
    for csv_file in csv_files:
        if DRY_RUN:
            print(f"Reading {csv_file}...")

        # Check if the CSV file is empty
        if os.stat(csv_file).st_size == 0:
            print(f"Skipping empty file: {csv_file}")
            continue

        # Read each non-empty CSV file into a DataFrame and append it to the list
        try:
            df_list.append(pd.read_csv(csv_file))
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

# make ./reports directory if it doesn't exist
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

# Get list of repositories for the user
url = f"https://api.github.com/{ORG_TYPE}/{TARGET}/repos"
headers = {"Authorization": f"token {TOKEN}"}
print(f"Getting list of repositories from {url}...")
response = requests.get(url, headers=headers)
if response.status_code != 200:
    print(f"Error: GitHub API returned status code {response.status_code}")
    print(response.text)
    exit(1)

repos = response.json()
#print(repos)

# Check if the response contains an error message
if "message" in repos and repos["message"] == "Not Found":
    print("Error: User not found. Double-check the username.")
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
            f"./reports/gitleaks_findings_{repo_bare_name}.csv",
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

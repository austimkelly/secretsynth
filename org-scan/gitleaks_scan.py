import subprocess
import glob
import os
import pandas as pd


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

# Function to concatenate CSV files
def concatenate_gitleaks_csv_files(gitleaks_report_filename, gitleaks_report_dir, logger=None):
    # Get a list of all CSV files in the {GITLEAKS_REPORTS_DIR} directory
    csv_files = glob.glob(f'{gitleaks_report_dir}/*.csv')

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
            if logger:
                logger.error(f"Error reading CSV file: {csv_file}")
            print(e)
            continue
        # Prepend a new column with the repository name
        df.insert(0, 'Owner', repo_owner)
        df.insert(1, 'Repository', repo_name)

        #print(f"dry-run: Reading {csv_file}...")

        # Read each non-empty CSV file into a DataFrame and append it to the list
        try:
            df_list.append(df)
        except pd.errors.EmptyDataError:
            print(f"Error: Empty CSV file: {csv_file}")
            if logger:
                logger.error(f"Error: Empty CSV file: {csv_file}")

    concatenated_df = pd.DataFrame()

    # Concatenate all the DataFrames in the list
    if df_list:
        concatenated_df = pd.concat(df_list, ignore_index=True)

    # Check if concatenated_df is empty
    if concatenated_df.empty:
        print(f"WARNING: No results to write to {gitleaks_report_filename}")
    else:
        # Write the concatenated DataFrame to a new CSV file
        print(f"Writing concatenated CSV file to ./{gitleaks_report_filename}...")
        concatenated_df.to_csv(f"{gitleaks_report_filename}", index=False)
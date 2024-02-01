
import subprocess
import pandas as pd
import json

import pandas as pd
import json

def extract_paths_from_provenance(provenance):
    if provenance:
        if provenance[0]['kind'] == 'git_repo':
            commit_provenance = provenance[0].get('commit_provenance', {})
            blob_path = commit_provenance.get('blob_path', '')
            repo_path = provenance[0].get('repo_path', '').split('.git')[0]
        elif provenance[0]['kind'] == 'file':
            blob_path = provenance[0].get('path', '')
            repo_path = ''
    else:
        blob_path = ''
        repo_path = ''
    return blob_path, repo_path

def json_to_csv(owner, json_data, csv_file_path):
    # Load json data
    data = json.loads(json_data)

    # Add owner to each record and parse provenance
    for record in data:
        record['owner'] = owner
        if 'provenance' in record['matches'][0]:
            record['blob_path'], record['repo_path'] = extract_paths_from_provenance(record['matches'][0]['provenance'])

    # Flatten json data
    flat_data = pd.json_normalize(data, record_path=['matches'], 
                                  meta=['owner', 'blob_path', 'repo_path'], 
                                  errors='ignore')

    # Write to csv
    flat_data.to_csv(csv_file_path, index=False)


def do_noseyparker_scan(owner, 
                        repo_name, 
                        repo_path, 
                        np_datastore_path,
                        dry_run,
                        logger=None):
    
    command = f"noseyparker scan {repo_path} --datastore {np_datastore_path}"
    print(f"Running NoseyParker on owner/repo: {owner}/{repo_name}, with command: {command}")
    
    if dry_run:
        print(f"dry-run: {command}")
        return

    np_datastore_path_with_owner = f"{np_datastore_path}/{owner}"

    result = subprocess.run(["noseyparker", "scan", repo_path, "--datastore", np_datastore_path_with_owner], capture_output=True, text=True)

    if result.returncode != 0:
        print("Unexpected error running NoseyParker. Please check the error log file for details.")
        logger.error(f"NoseyParker error: {result}")
        return

import subprocess

def run_noseyparker_report(owner, np_datastore_path, np_report_filename, logger=None):
    
    np_datastore_path_with_owner = f"{np_datastore_path}/{owner}"
    result = subprocess.run(["noseyparker", "report", "--datastore", np_datastore_path_with_owner, "--format=json"], capture_output=True, text=True)

    if result.returncode != 0:
        error_msg = f"Unexpected error running NoseyParker report. Please check the error log file for details."
        print(error_msg)
        if logger:
            logger.error(f"ERROR: NoseyParker: {result}")
        return

    # write the results to the report file
    with open(np_report_filename, 'w') as f:
        # convert the jsonl output to CSV
        json_to_csv(owner, result.stdout, np_report_filename)
        #f.write(result.stdout) # just write the jsonl output to the file
        
    return

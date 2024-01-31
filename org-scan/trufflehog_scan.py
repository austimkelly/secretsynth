import json
import subprocess
import csv

# target is the owner of the repository
# repo_name is the name of the repository
# repo_path is the path, relative to this script, to the repository
# report_filename is the path, relative to this script, to the report file
# dry_run is a boolean that indicates whether or not to actually run the scan
# logger is a logger object to use for error logging

def do_trufflehog_scan(target, 
                       repo_name, 
                       repo_path, 
                       report_filename,
                       dry_run=False,
                       logger=None):
    
    command = f"trufflehog filesystem {repo_path} --json"
    
    print(f"Running truffleog on owner/repo: {target}/{repo_name}, with command: {command}")
    
    if dry_run:
        print(f"dry-run: {command}")
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
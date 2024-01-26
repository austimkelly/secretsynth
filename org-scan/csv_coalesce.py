import csv
from fuzzywuzzy import fuzz

def unify_csv_files(trufflehog_file, gitleaks_file, output_file):
    unified_headers = ['source', 'owner', 'repo_name', 'file', 'line', 'secret', 'th_source_id', 'th_source_type', 'th_source_name', 'th_detector_type', 'th_detector_name', 'th_decoder_name', 'th_verified', 'th_raw', 'th_raw_v2', 'th_redacted', 'gl_owner', 'gl_commit', 'gl_symlink_file', 'gl_secret', 'gl_match', 'gl_start_line', 'gl_end_line', 'gl_start_column', 'gl_end_column', 'gl_author', 'gl_message', 'gl_date', 'gl_email', 'gl_fingerprint', 'gl_tags']

    with open(output_file, 'w', newline='') as f_out:
        writer = csv.DictWriter(f_out, fieldnames=unified_headers, extrasaction='ignore')
        writer.writeheader()

        # Trufflehog CSV
        with open(trufflehog_file, 'r') as f_in:
            reader = csv.DictReader(f_in)
            for row in reader:
                row['source'] = 'trufflehog'
                row['owner'] = row.pop('target', '')
                row['repo_name'] = row.pop('repo_name', '')
                row['file'] = row.pop('file', '')
                row['line'] = row.pop('line', '')
                row['secret'] = row.pop('raw', '')
                # only in trufflehog
                row['th_source_id'] = row.pop('source_id', '')
                row['th_source_type'] = row.pop('source_type', '')
                row['th_source_name'] = row.pop('source_name', '')
                row['th_detector_type'] = row.pop('detector_type', '')
                row['th_detector_name'] = row.pop('detector_name', '')
                row['th_decoder_name'] = row.pop('decoder_name', '')
                row['th_verified'] = row.pop('verified', '')
                row['th_raw'] = row.pop('raw', '')
                row['th_raw_v2'] = row.pop('raw_v2', '')
                row['th_redacted'] = row.pop('redacted', '')
                writer.writerow(row)

        # Gitleaks CSV
        with open(gitleaks_file, 'r') as f_in:
            reader = csv.DictReader(f_in)
            for row in reader:
                row['source'] = 'gitleaks'
                row['owner'] = row.pop('Owner', '')
                row['repo_name'] = row.pop('Repository', '')
                row['file'] = row.pop('File', '')
                row['line'] = row.pop('StartLine', '')
                row['secret'] = row.pop('Match', '')
                # only in gitleaks
                row['gl_endline'] = row.pop('EndLine', '')
                # write these to row Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags
                row['gl_commit'] = row.pop('Commit', '')
                row['gl_symlink_file'] = row.pop('SymlinkFile', '')
                row['gl_secret'] = row.pop('Secret', '')
                row['gl_match'] = row.pop('Match', '')
                row['gl_start_line'] = row.pop('StartLine', '')
                row['gl_end_line'] = row.pop('EndLine', '')
                row['gl_start_column'] = row.pop('StartColumn', '')
                row['gl_end_column'] = row.pop('EndColumn', '')
                row['gl_author'] = row.pop('Author', '')
                row['gl_message'] = row.pop('Message', '')
                row['gl_date'] = row.pop('Date', '')
                row['gl_email'] = row.pop('Email', '')
                row['gl_fingerprint'] = row.pop('Fingerprint', '')
                row['gl_tags'] = row.pop('Tags', '')

                writer.writerow(row)


def find_matches(input_file, output_file):
    # Define the headers for the input and output CSV files
    input_headers = ['source', 'owner', 'repo_name', 'file', 'line', 'secret', 'th_source_id', 'th_source_type', 'th_source_name', 'th_detector_type', 'th_detector_name', 'th_decoder_name', 'th_verified', 'th_raw', 'th_raw_v2', 'th_redacted', 'gl_owner', 'gl_commit', 'gl_symlink_file', 'gl_secret', 'gl_match', 'gl_start_line', 'gl_end_line', 'gl_start_column', 'gl_end_column', 'gl_author', 'gl_message', 'gl_date', 'gl_email', 'gl_fingerprint', 'gl_tags']
    output_headers = ['match', 'match_score', 'match_source', 'matched_on_source', 'match_reason'] + input_headers

    # Open the input CSV file and read the data into a list of dictionaries
    with open(input_file, 'r') as f_in:
        reader = csv.DictReader(f_in)
        data = [{k: row[k] for k in input_headers} for row in reader]

    matches = []
    # Loop over each row in the data
    for i, row in enumerate(data):
        # Compare the current row with every other row
        for j, other_row in enumerate(data):
            # Skip the comparison if it's the same row, or if the repo_name is not the same, or if the source (scanning tool used) is the same
            if i == j or row['repo_name'] != other_row['repo_name'] or row['source'] == other_row['source']:
                continue

            # Calculate the similarity score for the secret, line, and file fields
            secret_score = fuzz.ratio(row['secret'], other_row['secret'])
            line_score = fuzz.ratio(row['line'], other_row['line'])
            file_score = fuzz.ratio(row['file'], other_row['file'])

            # Calculate the average of the three scores
            match_score = (secret_score + line_score + file_score) / 3

            # If the match score is greater than 50, consider it a match
            if match_score > 50:
                # Create a new dictionary for the output row, copying all fields from the input row
                output_row = {k: row[k] for k in input_headers}
                # Replace the 'source' field with 'match'
                output_row['match'] = output_row.pop('source')
                # Add the match score, match source, matched on source, and match reason fields
                output_row['match_score'] = match_score
                output_row['match_source'] = row['source']
                output_row['matched_on_source'] = other_row['source']
                output_row['match_reason'] = f"Matched on secret: {row['secret']}, line: {row['line']}, file: {row['file']}"
                # Add the output row to the list of matches
                matches.append(output_row)

    # Remove duplicate matches
    matches = [dict(t) for t in set(tuple(d.items()) for d in matches)]

    # Write the matches to the output CSV file
    with open(output_file, 'w', newline='') as f_out:
        writer = csv.DictWriter(f_out, fieldnames=output_headers)
        writer.writeheader()
        writer.writerows(matches)

# Call the functions
unify_csv_files('trufflehog_results_202401260938.csv', 'gitleaks_report_concat.csv', 'unified.csv')
find_matches('unified.csv', 'matches.csv')


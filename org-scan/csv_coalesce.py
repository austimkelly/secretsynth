import csv
from fuzzywuzzy import fuzz
import hashlib
import sys
import os

csv.field_size_limit(sys.maxsize)

# Result is deterministic, but not reversible
def hash_secret(secret):
    # Create a hash object
    hash_object = hashlib.sha256()
    # Update the hash object with the bytes of the 'secret' value
    hash_object.update(secret.encode())
    return hash_object.hexdigest()

# Summary
# Merge all CSV files from all tools into a single CSV file. If the input files do not exist, they will be skipped.
# Input:
#   keep_secrets: boolean indicating whether or not to keep secrets in the output file
#   trufflehog_file: path to the trufflehog CSV file
#   gitleaks_file: path to the gitleaks CSV file
#   ghas_alerts_file: path to the GHAS secrets CSV file
#   np_report_filename: path to the NoseyParker report CSV file
#   output_file: path to the output CSV file
# Output:
#   None
def merge_csv_all_tools(keep_secrets,
                        trufflehog_file, 
                        gitleaks_file, 
                        ghas_alerts_file,
                        np_report_filename, 
                        output_file):
    unified_headers = ['source', 'owner', 'repo_name', 'file', 'line', 'secret', 'match', 'detector',
                        'th_source_id', 'th_source_type', 'th_source_name', 'th_detector_type', 'th_detector_name', 'th_decoder_name', 'th_verified', 'th_raw', 'th_raw_v2', 'th_redacted', 
                        'gl_owner', 'gl_commit', 'gl_symlink_file', 'gl_secret', 'gl_match', 'gl_start_line', 'gl_end_line', 'gl_start_column', 'gl_end_column', 'gl_author', 'gl_message', 'gl_date', 'gl_email', 'gl_fingerprint', 'gl_tags',
                        'ghas_number', 'ghas_rule', 'ghas_state', 'ghas_created_at', 'ghas_html_url',
                        'np_provenance', 'np_blob_id', 'np_capture_group_index', 'np_match_content', 'np_blob_metadata_id', 'np_blob_metadata_num_bytes', 'np_blob_metadata_mime_essence', 'np_blob_metadata_charset', 'np_location_offset_span_start', 'np_location_offset_span_end', 'np_location_source_span_start_line', 'np_location_source_span_start_column', 'np_location_source_span_end_line', 'np_location_source_span_end_column', 'np_snippet_before', 'np_snippet_after'
                       ]

    with open(output_file, 'w', newline='') as f_out:
        writer = csv.DictWriter(f_out, fieldnames=unified_headers, extrasaction='ignore')
        writer.writeheader()

        if os.path.exists(trufflehog_file):
            # Trufflehog CSV
            with open(trufflehog_file, 'r') as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    row['source'] = 'trufflehog'
                    row['owner'] = row.pop('target', '')
                    row['repo_name'] = row.pop('repo_name', '')
                    row['file'] = row.pop('file', '')
                    row['line'] = row.pop('line', '')
                    if not keep_secrets:
                        row['secret'] = hash_secret(row.pop('raw', ''))
                        row['match'] = hash_secret(row.pop('raw_v2', ''))
                    else:
                        row['secret'] = row.pop('raw', '')
                        row['match'] = row.pop('raw_v2', '') 
                    row['detector'] = row.pop('detector_name', '')
                    # only in trufflehog
                    row['th_source_id'] = row.pop('source_id', '')
                    row['th_source_type'] = row.pop('source_type', '')
                    row['th_source_name'] = row.pop('source_name', '')
                    row['th_detector_type'] = row.pop('detector_type', '')
                    row['th_detector_name'] = row.pop('detector_name', '')
                    row['th_decoder_name'] = row.pop('decoder_name', '')
                    row['th_verified'] = row.pop('verified', '')
                    if not keep_secrets:
                        row['th_raw'] = hash_secret(row.pop('raw', ''))
                        row['th_raw_v2'] = hash_secret(row.pop('raw_v2', ''))
                        row['th_redacted'] = hash_secret(row.pop('redacted', ''))
                    else:
                        row['th_raw'] = row.pop('raw', '')
                        row['th_raw_v2'] = row.pop('raw_v2', '')    
                        row['th_redacted'] = row.pop('redacted', '')
                    writer.writerow(row)

        if os.path.exists(gitleaks_file):
            # Gitleaks CSV
            with open(gitleaks_file, 'r') as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    row['source'] = 'gitleaks'
                    row['owner'] = row.pop('Owner', '')
                    row['repo_name'] = row.pop('Repository', '')
                    row['file'] = row.pop('File', '')
                    row['line'] = row.pop('StartLine', '')
                    if not keep_secrets:
                        row['secret'] = hash_secret(row.pop('Secret', ''))
                        row['match'] = hash_secret(row.pop('Match', ''))
                    else:
                        row['secret'] = row.pop('Secret', '')
                        row['match'] = row.pop('Match', '')
                    row['detector'] = row.pop('Fingerprint', '')
                    # only in gitleaks
                    row['gl_endline'] = row.pop('EndLine', '')
                    # write these to row Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags
                    row['gl_commit'] = row.pop('Commit', '')
                    row['gl_symlink_file'] = row.pop('SymlinkFile', '')
                    if not keep_secrets:
                        row['gl_secret'] = hash_secret(row.pop('Secret', ''))
                        row['gl_match'] = hash_secret(row.pop('Match', ''))
                    else:
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

        if os.path.exists(ghas_alerts_file):
            # GHAS Secrets CSV
            with open(ghas_alerts_file, 'r') as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    # Schema: owner,repo,number,rule,state,created_at,html_url
                    row['source'] = 'ghas'
                    row['owner'] = row.pop('owner', '')
                    row['repo_name'] = row.pop('repo', '')
                    row['file'] = row.pop('html_url', '')
                    row['line'] = row.pop('unavailable - see alert in Github', '')
                    row['secret'] = row.pop('unavailable - see alert in Github', '')
                    row['match'] = row.pop('unavailable - see alert in Github', '')
                    row['detector'] = row.pop('rule', '')
                    # only in ghas
                    row['ghas_number'] = row.pop('number', '')
                    row['ghas_rule'] = row.pop('rule', '')
                    row['ghas_state'] = row.pop('state', '')
                    row['ghas_created_at'] = row.pop('created_at', '')
                    row['ghas_html_url'] = row.pop('html_url', '')

                    writer.writerow(row)
        
        if os.path.exists(np_report_filename):
            # NoseyParker CSV
            with open(np_report_filename, 'r') as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    # Schema: provenance,blob_id,capture_group_index,match_content,rule_name,blob_metadata.id,blob_metadata.num_bytes,blob_metadata.mime_essence,blob_metadata.charset,location.offset_span.start,location.offset_span.end,location.source_span.start.line,location.source_span.start.column,location.source_span.end.line,location.source_span.end.column,snippet.before,snippet.matching,snippet.after,owner
                    row['source'] = 'noseyparker'
                    row['owner'] = row.pop('owner', '')
                    row['repo_name'] = row.pop('TBD', '')
                    row['file'] = row.pop('TBD', '')
                    row['line'] = row.pop('location.source_span.start.line', '')
                    if not keep_secrets:
                        row['match'] = hash_secret(row.pop('snippet.matching', ''))
                        row['secret'] = hash_secret(row.pop('match_content', ''))
                    else:
                        row['match'] = row.pop('snippet.matching', '')
                        row['secret'] = row.pop('match_content', '')
                    row['detector'] = row.pop('rule_name', '')
                    # only in noseyparker
                    row['np_provenance'] = row.pop('provenance', '')
                    row['np_rule'] = row.pop('rule_name', '')
                    row['np_blob_id'] = row.pop('blob_id', '')
                    row['np_capture_group_index'] = row.pop('capture_group_index', '')
                    row['np_match_content'] = row.pop('match_content', '')
                    row['np_blob_metadata_id'] = row.pop('blob_metadata.id', '')
                    row['np_blob_metadata_num_bytes'] = row.pop('blob_metadata.num_bytes', '')
                    row['np_blob_metadata_mime_essence'] = row.pop('blob_metadata.mime_essence', '')
                    row['np_blob_metadata_charset'] = row.pop('blob_metadata.charset', '')
                    row['np_location_offset_span_start'] = row.pop('location.offset_span.start', '')
                    row['np_location_offset_span_end'] = row.pop('location.offset_span.end', '')
                    row['np_location_source_span_start_line'] = row.pop('location.source_span.start.line', '')
                    row['np_location_source_span_start_column'] = row.pop('location.source_span.start.column', '')
                    row['np_location_source_span_end_line'] = row.pop('location.source_span.end.line', '')
                    row['np_location_source_span_end_column'] = row.pop('location.source_span.end.column', '')
                    if not keep_secrets:
                        row['np_snippet_before'] = hash_secret(row.pop('snippet.before', ''))
                        row['np_snippet_after'] = hash_secret(row.pop('snippet.after', ''))
                    else: # keep secrets
                        row['np_snippet_before'] = row.pop('snippet.before', '')
                        row['np_snippet_after'] = row.pop('snippet.after', '')

                    writer.writerow(row)

def find_matches(input_file, output_file):
    # Define the headers for the input and output CSV files
    input_headers = ['source', 'owner', 'repo_name', 'file', 'line', 'secret', 'th_source_id', 'th_source_type', 'th_source_name', 'th_detector_type', 'th_detector_name', 'th_decoder_name', 'th_verified', 'th_raw', 'th_raw_v2', 'th_redacted', 'gl_owner', 'gl_commit', 'gl_symlink_file', 'gl_secret', 'gl_match', 'gl_start_line', 'gl_end_line', 'gl_start_column', 'gl_end_column', 'gl_author', 'gl_message', 'gl_date', 'gl_email', 'gl_fingerprint', 'gl_tags']
    output_headers = ['match', 'match_score', 'match_source', 'matched_on_source', 'match_reason'] + input_headers + [f'matched_{key}' for key in input_headers if key.startswith('gl_') or key.startswith('th_')]

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
                for key in other_row:
                    if key.startswith('gl_') or key.startswith('th_'):
                        output_row[f'matched_{key}'] = other_row[key]
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



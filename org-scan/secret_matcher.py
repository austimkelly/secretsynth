from fuzzywuzzy import fuzz
import csv

def find_matches(input_file, output_file):
    # Define the headers for the input and output CSV files
    input_headers = ['source', 'owner', 'repo_name', 'file', 'line', 'secret', 'match',
                      'th_source_id', 'th_source_type', 'th_source_name', 'th_detector_type', 'th_detector_name', 'th_decoder_name', 'th_verified', 'th_raw', 'th_raw_v2', 'th_redacted',
                      'gl_owner', 'gl_commit', 'gl_symlink_file', 'gl_secret', 'gl_match', 'gl_start_line', 'gl_end_line', 'gl_start_column', 'gl_end_column', 'gl_author', 'gl_message', 'gl_date', 'gl_email', 'gl_fingerprint', 'gl_tags'
                      ]
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

            # Calculate the similarity score for the secret (raw value), line, and file fields
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
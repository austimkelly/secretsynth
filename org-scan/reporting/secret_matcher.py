from fuzzywuzzy import fuzz
import csv

def find_matches(input_file, output_file, fuzz_factor):
    with open(input_file, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        matches = {}

        for row in reader:
            secret = row['secret']
            owner = row['owner']  
            repo = row['repo_name']
            source = row['source'] 

            # Perform fuzzy matching operation on the 'secret' value
            for key in matches.keys():
                if fuzz.ratio(secret, key) > fuzz_factor and matches[key]['owner'] == owner and matches[key]['repo_name'] == repo:
                    # Update the existing row
                    matches[key]['total_matches'] += 1
                    matches[key]['tools_matched_on'].add(source)
                    break
            else:
                # Add a new row
                row['total_matches'] = 1
                row['tools_matched_on'] = {source}
                matches[secret] = row

    fieldnames = reader.fieldnames
    # Rearrange the fieldnames to make 'total_matches' the 5th column
    if 'total_matches' in fieldnames:
        fieldnames.remove('total_matches')
    fieldnames.insert(4, 'total_matches')
    
    # Move 'tools_matched_on' column to the 6th column
    if 'tools_matched_on' in fieldnames:
        fieldnames.remove('tools_matched_on')
    fieldnames.insert(5, 'tools_matched_on')

    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in matches.values():
            row['tools_matched_on'] = ', '.join(row['tools_matched_on'])  # Use 'tools_matched_on' instead of 'tools'
            writer.writerow(row)

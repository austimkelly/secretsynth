import pandas as pd

def get_table_style(table_links):
    # Style the DataFrame
    styled_table_links =  table_links.style.set_table_styles([
        {'selector': 'table', 'props': [('border', '1px solid black')]},
        {'selector': 'tr:nth-of-type(odd)', 'props': [('background', '#eee')]},
        {'selector': 'tr:nth-of-type(even)', 'props': [('background', '#fff')]},
        {'selector': 'th', 'props': [('background', '#606060'), ('color', 'white'), ('font-weight', 'bold')]}
    ])

    # Hide the index
    styled_table_links.hide_index()
    return styled_table_links

def output_to_html(metrics, 
                   repo_metrics, 
                   detector_metrics,
                   merged_report_name, 
                   ghas_secret_alerts_filename, 
                   matches_report_name,
                   error_logfile, 
                   report_path 
                   ):
    
    # Define descriptions for Report Links
    descriptions = ['The merged report contains the row-by-row of all secrets from all secret scanners. The merged reports create a few common fields to make it easier to aggregate and filter across multiple secret scanning solutions.', 
                    'GHAS alerts are the alerts that are pulled down from the GitHub Advanced Security (GHAS) API. GHAS secret alerts to do not contain secret, line, or file information from the API.', 
                    'These are secrets that have at least one match among the other tools.', 
                    'Any processing errors are logged here. If the total errors is > 0, then your results may be incomplete.']
    file_paths = [merged_report_name, ghas_secret_alerts_filename, matches_report_name, error_logfile]
    # Create a DataFrame with links to the raw report files
    report_links = pd.DataFrame({
        'Report Name': ['Merged Report', 'GHAS Secret Alerts', 'Matches Report', "Error Log"],
        'Description': descriptions,
        'CSV Link': [f'<a href="{file_path}">{file_path}</a>' for file_path in file_paths]
    })

    # Convert the DataFrames to HTML
    metrics_html = get_table_style(metrics).render(index=False)
    repo_metrics_html = get_table_style(repo_metrics).render(index=False)
    detector_metrics_html = get_table_style(detector_metrics).render(index=False)
    report_links_html = get_table_style(report_links).render(index=False)

    # Write the HTML to a file
    with open(report_path, 'w') as f:
        f.write('<h1>Top Level Summary</h1>')
        f.write(metrics_html)
        f.write('<h1>Repo-Level Metrics</h1>')
        f.write(repo_metrics_html)
        f.write('<h1>Detector Metrics</h1>')
        f.write(detector_metrics_html)
        f.write('<h1>Report Links</h1>')
        f.write(report_links_html)

    # Print the absolute path of the HTML file
    print(f"HTML file written to: {report_path}")
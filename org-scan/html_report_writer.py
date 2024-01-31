import pandas as pd

def output_to_html(metrics, 
                   merged_report_name, 
                   ghas_secret_alerts_filename, 
                   matches_report_name,
                   error_logfile, 
                   report_path 
                   ):
    # Create a DataFrame with links to the raw report files
    report_links = pd.DataFrame({
        'Report Name': ['Merged Report', 'GHAS Secret Alerts', 'Matches Report', "Error Log"],
        'CSV Link': [f'<a href="{merged_report_name}">{merged_report_name}</a>',
                     f'<a href="{ghas_secret_alerts_filename}">{ghas_secret_alerts_filename}</a>',
                     f'<a href="{matches_report_name}">{matches_report_name}</a>',
                     f'<a href="{error_logfile}">{error_logfile}</a>']
    })

    # Convert the DataFrames to HTML
    metrics_html = metrics.to_html()
    report_links_html = report_links.to_html(escape=False)

    # Write the HTML to a file
    with open(report_path, 'w') as f:
        f.write('<h1>Metrics</h1>')
        f.write(metrics_html)
        f.write('<h1>Report Links</h1>')
        f.write(report_links_html)

    # Print the absolute path of the HTML file
    print(f"HTML file written to: {report_path}")
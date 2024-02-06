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
                   timing_metrics,
                   merged_report_name, 
                   ghas_secret_alerts_filename, 
                   matches_report_name,
                   error_logfile, 
                   report_path 
                   ):
    
    # Define descriptions for Report Links
    descriptions = ['The merged report contains the row-by-row of all secrets from all secret scanners. The merged reports create a few common fields to make it easier to aggregate and filter across multiple secret scanning solutions.', 
                    'GHAS alerts are the alerts that are pulled down from the GitHub Advanced Security (GHAS) API. GHAS secret alerts to do not contain secret, line, or file information from the API.', 
                    'Experimental. These are secrets that have at least one match among the other tools. Consider these results experimental only.', 
                    'Any processing errors are logged here. If the total errors is > 0, then your results may be incomplete.']
    file_paths = [merged_report_name, ghas_secret_alerts_filename, matches_report_name, error_logfile]
    # Create a DataFrame with links to the raw report files
    report_links = pd.DataFrame({
        'Report Name': ['Merged Report', 'GHAS Secret Alerts', 'Matches Report', "Error Log"],
        'Description': descriptions,
        'CSV Link': [f'<a href="{file_path}">{file_path}</a>' for file_path in file_paths]
    })

    # Set pandas precision
    pd.set_option('precision', 2)
    
    total_time = sum(value for key, value in timing_metrics.items() if "_time" in key)
    
    timing_metrics_data = []
    for function, value in timing_metrics.items():
        if "_time" in function:
            hours, remainder = divmod(value, 3600)
            minutes, seconds = divmod(remainder, 60)
            time_str = f"{int(hours)} hours {int(minutes)} minutes {seconds:.2f} seconds"
            percentage = (value / total_time) * 100 if total_time != 0 else 0
            timing_metrics_data.append({"Function": function, "Time (seconds)": time_str, "Percentage of Total Time": percentage})
        elif "_percentage" in function:
            timing_metrics_data.append({"Function": function, "Time (seconds)": value, "Percentage of Total Time": None})
    timing_metrics_df = pd.DataFrame(timing_metrics_data)

    # Apply style and convert to HTML
    timing_metrics_html = get_table_style(timing_metrics_df).render(index=False)

    # Convert the DataFrames to HTML
    metrics_html = get_table_style(metrics).render(index=False)
    repo_metrics_html = get_table_style(repo_metrics).render(index=False)
    detector_metrics_html = get_table_style(detector_metrics).render(index=False)
    report_links_html = get_table_style(report_links).render(index=False)

    # Define the summary text for each section
    about_secretsynth_text = '<p>Secret Synth is a meta-secret scanner solution that wraps popular source code secret scanning solutions such as gitleaks, Nosey Parker, and Trufflehog.</p>'
    disclaimer_text = '<p>By default, aggregated reports hash secret values. While this can be overridden, care should be taken how results are shared. There may be known and unknown bugs in the calculations of this tool. You are expected to do your own due diligence to check the accuracy of these findings. The use or not use of any scanning solution should not be take as an endorsement to use any particular scanning solution. If you want to see a solution added, drop a request in the repo linked at the bottom of this document.</p>'
    license_text = '<p>Secret Synth is distributed under MIT License. Source code for Secret Synth can be found <a href="https://github.com/austimkelly/gitleaks-utils">here</a></p>'
    top_level_summary_text = '<p>Here is an overview of the secret scan results. Check the tools used and the error count to see if there may have been problems with the scan.</p>'
    repo_level_summary_text = '<p>This section provides detailed metrics for each repository scanned. This just gives you an idea of the quantity of secrets discovered by each tool and the total number of secrets in the entire repository.</p>'
    detector_summary_text = '<p>Every tool emits a detector type. The table below just gives you an aggregated view of the types of secrets that have been found and the magnitude of each. This does not indicate which tool found the secret.</p>'
    report_links_summary_text = '<p>Here you can find the raw data of all the secrets in the merged_scan_results_report. The first few columns represent the generic information found among all tools. Any fields starting with np_, gl_, gh_, or th_ are specifics to those tools.</p>'
    timing_metrics_summary_text = '<p>Total scan time for each tool and as a percentage of whole. GHAS Secrets is never included here since local scanning is not supported.</p>'   

    # Write the HTML to a file
    with open(report_path, 'w') as f:
        f.write('<h1>About Secret Synth</h1>')
        f.write(about_secretsynth_text)
        f.write('<h2>Disclaimer</h2>')
        f.write(disclaimer_text)
        f.write('<h1>Top Level Summary</h1>')
        f.write(top_level_summary_text)
        f.write(metrics_html)
        f.write('<h2>Timing Metrics</h2>')
        f.write(timing_metrics_summary_text)
        f.write(timing_metrics_html)
        f.write('<h1>Repo-Level Metrics</h1>')
        f.write(repo_level_summary_text)
        f.write(repo_metrics_html)
        f.write('<h1>Detector Metrics</h1>')
        f.write(detector_summary_text)
        f.write(detector_metrics_html)
        f.write('<h1>Report Links</h1>')
        f.write(report_links_summary_text)
        f.write(report_links_html)
        f.write('<h1>License and Source Code</h1>')
        f.write(license_text)


    # Print the absolute path of the HTML file
    print(f"HTML file written to: {report_path}")
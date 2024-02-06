import requests
import csv

verbose_logging = False

def fetch_repos(account_type, account, headers, logger=None, page=1, per_page=100):
    repos = []
    while True:
        repos_url = f'https://api.github.com/{account_type}/{account}/repos?page={page}&per_page={per_page}'
        if verbose_logging:
            print(f"Calling {repos_url}...")
        response = requests.get(repos_url, headers=headers)
        data = response.json()
        
        # Check if data is a dictionary containing an error message
        if isinstance(data, dict) and "message" in data:
            print(f"ERROR: Cannot execute API to fetch repos for GHAS secrets alert: {data['message']}")
            if logger:
                logger.error(f"ERROR: Cannot execute API to fetch repos for GHAS secrets alert: {data['message']}") 
            break

        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    
    return repos

# Returns a list of repos where secret scanning is disabled
def fetch_ghas_secret_scanning_alerts(owner_type, 
                                      owners, headers, 
                                      report_name, 
                                      dry_run=False, 
                                      logger=None):
    
    if dry_run:
        print(f"dry-run: Calling Github REST API for all repos under orgs: {owners}")
        return

    # Open the CSV file
    with open(report_name, 'w', newline='') as csvfile:
        fieldnames = ['repo', 'rule', 'owner', 'number', 'created_at', 'updated_at', 'url', 'html_url', 'locations_url', 'state', 'secret_type', 
                  'secret_type_display_name', 'secret', 'validity', 'resolution', 'resolved_by', 'resolved_at', 
                  'resolution_comment', 'push_protection_bypassed', 'push_protection_bypassed_by', 
                  'push_protection_bypassed_at']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        repos_secret_scanning_disabled = []

        writer.writeheader()
        for owner in owners:
            repos = fetch_repos(owner_type, owner, headers, logger=logger)
            # For each repo, get the secret scanning alerts

            # If verbose logging enabled, print the list of repos names only and the total number of repos
            if verbose_logging:
                print(f"List of repos for {owner}: {', '.join([repo['name'] for repo in repos])}")
                print(f"Total number of repos to get GHAS Security Alerts for {owner}: {len(repos)}")

            for repo in repos:
                
                # If verbose logging enabled, print the repo name
                if verbose_logging:
                    print(f"****************Getting GHAS Security Alerts for {owner}/{repo['name']}")

                if verbose_logging:
                    print(f"Calling https://api.github.com/repos/{owner}/{repo['name']}/secret-scanning/alerts ...")

                # https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository
                alerts_response = requests.get(f'https://api.github.com/repos/{owner}/{repo["name"]}/secret-scanning/alerts', headers=headers)
                alerts = alerts_response.json()

                # if verbose and alert, print the alerts for the repo
                if verbose_logging:
                    print(f"Alerts for {owner}/{repo['name']}: {alerts}")

                # Check if message contains {'message': 'Resource not accessible by personal access token'} 
                if isinstance(alerts, dict) and 'message' in alerts and alerts['message'] == 'Resource not accessible by personal access token':
                    print(f"ERROR: Invalid Person Access Token. Cannot fetch security alerts for {repo['name']}: {alerts['message']}")
                    if logger:
                        logger.error(f"ERROR: Invalid Github Person Access Token. Cannot fetch security alerts for {repo['name']}: {alerts['message']}")
                    continue

                # If the response is a dictionary with a 'message' key, skip this iteration
                if isinstance(alerts, dict) and 'message' in alerts:
                    if verbose_logging:
                       print(f"Skipping {repo['name']}: {alerts['message']}")
                       
                    if 'message' in alerts and alerts['message'] == 'Secret scanning is disabled on this repository.':
                        repos_secret_scanning_disabled.append(repo)
                        if logger:
                            logger.info(f"GHAS Secret scanning is disabled on repository: {repo['name']}")
                    continue

                # Write each alert to the CSV file
                for alert in alerts:

                    # if verbose, print the row to be written to the CSV file
                    # if verbose_logging:
                    #     print(f"Alert found: {alert}")

                    writer.writerow({
                        'repo': repo['name'],
                        'rule': alert['secret_type'],  # Use 'secret_type' instead of 'rule'
                        'owner': owner,  # org or user
                        'number': alert['number'],
                        'created_at': alert['created_at'],
                        'updated_at': alert['updated_at'],
                        'url': alert['url'],
                        'html_url': alert['html_url'],
                        'locations_url': alert['locations_url'],
                        'state': alert['state'],
                        'secret_type': alert['secret_type'],
                        'secret_type_display_name': alert['secret_type_display_name'],
                        'secret': alert['secret'],
                        'validity': alert['validity'],
                        'resolution': alert['resolution'],
                        'resolved_by': alert['resolved_by'],
                        'resolved_at': alert['resolved_at'],
                        'resolution_comment': alert['resolution_comment'],
                        'push_protection_bypassed': alert['push_protection_bypassed'],
                        'push_protection_bypassed_by': alert['push_protection_bypassed_by'],
                        'push_protection_bypassed_at': alert['push_protection_bypassed_at']
                    })

            return repos_secret_scanning_disabled
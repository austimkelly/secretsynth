import requests
import csv

verbose_logging = True

def fetch_repos(account_type, account, headers, page=1, per_page=100):
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
            break

        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    
    return repos

def fetch_ghas_secret_scanning_alerts(owner_type, owners, headers, report_name):
    
    # Open the CSV file
    with open(report_name, 'w', newline='') as csvfile:
        fieldnames = ['owner', 'repo', 'number', 'rule', 'state', 'created_at', 'html_url']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        repos_without_secrets_scanning = []

        writer.writeheader()
        for owner in owners:
                repos = fetch_repos(owner_type, owner, headers)
                # For each repo, get the secret scanning alerts
                for repo in repos:
                    alerts_response = requests.get(f'https://api.github.com/repos/{owner}/{repo["name"]}/secret-scanning/alerts', headers=headers)
                    alerts = alerts_response.json()

                    # print alerts json response for each repo
                    if verbose_logging:
                        print(f"Calling https://api.github.com/repos/{owner}/{repo['name']}/secret-scanning/alerts ...")
                        print(alerts)

                    # Check if message contains {'message': 'Resource not accessible by personal access token'} 
                    if isinstance(alerts, dict) and 'message' in alerts and alerts['message'] == 'Resource not accessible by personal access token':
                        print(f"ERROR: Invalid Person Access Token. Cannot fetch security alerts for {repo['name']}: {alerts['message']}")
                        continue

                    # If the response is a dictionary with a 'message' key, skip this iteration
                    if isinstance(alerts, dict) and 'message' in alerts:
                        print(f"Skipping {repo['name']}: {alerts['message']}")
                        if 'message' in alerts and alerts['message'] == 'Secret scanning is disabled on this repository.':
                            repos_without_secrets_scanning.append(repo)
                        continue

                    # Write each alert to the CSV file
                    for alert in alerts:
                        writer.writerow({
                            'owner': owner,  # org or user
                            'repo': repo['name'],
                            'number': alert['number'],
                            'rule': alert['secret_type'],  # Use 'secret_type' instead of 'rule'
                            'state': alert['state'],
                            'created_at': alert['created_at'],
                            'html_url': alert['html_url'],
                        })

                    return repos_without_secrets_scanning
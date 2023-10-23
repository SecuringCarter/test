import requests
from datetime import datetime
import pytz
import pandas as pd
import os

token = os.environ["TOKEN_SECRET"]

#github_pat = os.environ.get('GITHUB_PAT')

# Define the URL for the GitHub Security Advisories API
url = '  https://api.github.com/orgs/SecuringCarter/security-advisories'

# Set up the request headers with the authorization token
headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': f'Bearer {token}',
    'X-GitHub-Api-Version': '2022-11-28'
}

# Initialize an empty list to store responses
responses = []

try:
    # Send a GET request to the GitHub API
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        advisories = response.json()
        # Now, 'advisories' contains the security advisories data.
        # Append the response data to the 'responses' list
        responses.append(advisories)
        print(advisories)
    else:
        print(f"Request failed with status code {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"An error occurred: {e}")

for idx, advisory_response in enumerate(responses, 1):
    print(f"Response {idx}:")
    print(advisory_response)

# Extract specified fields and create a DataFrame
data = {
    "ghsa_id": [item["ghsa_id"] for item in advisory_response],
    "cve_id": [item["cve_id"] for item in advisory_response],
    "html_url": [item["html_url"] for item in advisory_response],
    "summary": [item["summary"] for item in advisory_response],
    "severity": [item["severity"] for item in advisory_response],
    "state": [item["state"] for item in advisory_response],
    "created_at": [item["created_at"] for item in advisory_response],
    "updated_at": [item["updated_at"] for item in advisory_response]
}
df = pd.DataFrame(data)

# Filter to active incidents
filtered_df = df[df['state'] != 'published']

# Split the repository name from the url and add it as a new column 'repo'
filtered_df['repo'] = filtered_df['html_url'].str.split('/').str[4]

df_filled = filtered_df.fillna(0)

# Convert the 'date' column to datetime objects and ensure they are in UTC
df_filled['created_at'] = pd.to_datetime(df_filled['created_at'], format="%Y-%m-%dT%H:%M:%SZ").dt.tz_localize('UTC')
df_filled['updated_at'] = pd.to_datetime(df_filled['updated_at'], format="%Y-%m-%dT%H:%M:%SZ").dt.tz_localize('UTC')

# Get the current time in UTC
current_time = datetime.now(pytz.utc)

# Make the current time timezone-aware
current_time = current_time.replace(tzinfo=pytz.utc)

# Calculate the difference in days for each date
df_filled['days_open'] = (current_time - df_filled['created_at']).dt.days
df_filled['days_since_update'] = (current_time - df_filled['updated_at']).dt.days

# Drop the time component and keep only the date
df_filled['created_at'] = df_filled['created_at'].dt.date
df_filled['updated_at'] = df_filled['updated_at'].dt.date

# File output
df_filled.to_csv('output.csv', index=False)  # 'output.csv' is the filename
# Strava CTA

Automatically check for new Strava activities and update their descriptions to include a call to action (CTA).

## Features

- Polls Strava API for new activities created since midnight UTC
- Checks if activities already contain the CTA content
- Updates activities missing the CTA content
- Handles token refresh using the Strava OAuth flow
- Automatically sets GitHub Actions environment variables when tokens are refreshed
- Runs as a GitHub Action or standalone script

## Setup

### Prerequisites

- Python 3.10 or higher
- Strava API credentials (Client ID, Client Secret, and Authorization Code or Refresh Token)
- For GitHub Actions integration: The workflow runs with GitHub CLI pre-installed

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/strava-cta.git
cd strava-cta

# Install dependencies
uv sync
```

### Configuration

Set the following environment variables:

```bash
# Required Strava API credentials
export STRAVA_CLIENT_ID="your_client_id"
export STRAVA_CLIENT_SECRET="your_client_secret"
export STRAVA_ACCESS_TOKEN="your_access_token"
export STRAVA_REFRESH_TOKEN="your_refresh_token"
export STRAVA_TOKEN_EXPIRES_AT="token_expiration_timestamp"

# Optional configuration
export POLLING_INTERVAL_MINUTES="5"  # Default: 5 minutes
```

### CTA Content

Create a `cta.txt` file with your call to action content in the root directory of the project.

## Usage

### Running as a standalone script

```bash
# Run the activity checker
python -m strava_cta.check_activities

# You can also provide tokens directly as arguments
python -m strava_cta.check_activities --access-token YOUR_ACCESS_TOKEN --refresh-token YOUR_REFRESH_TOKEN --token-expires YOUR_TOKEN_EXPIRES_AT
```

### Running with GitHub Actions

1. Add the required secrets to your GitHub repository:
   - `STRAVA_CLIENT_ID`: Your Strava API client ID
   - `STRAVA_CLIENT_SECRET`: Your Strava API client secret
   - `STRAVA_ACCESS_TOKEN`: Your Strava API access token
   - `STRAVA_REFRESH_TOKEN`: Your Strava API refresh token
   - `STRAVA_TOKEN_EXPIRES_AT`: Your Strava token expiration timestamp

2. Create a workflow file (example provided in `.github/workflows/strava-cta-checker.yml`)

3. The workflow will run on the configured schedule and automatically update your Strava activities with the CTA content.

4. You can manually trigger the workflow from the Actions tab in your repository.

5. Ensure the workflow has the necessary permissions to update secrets:
   ```yaml
   permissions:
     contents: read
     actions: write
   ```

## Authorization with Strava

To use this tool, you need to authenticate with Strava. The `strava_cta.authorize_strava` module provides a complete implementation of the Strava OAuth flow:

### Step 1: Generate an Authorization URL

```bash
# Generate the authorization URL
python -m strava_cta.authorize_strava --client-id YOUR_CLIENT_ID
```

This will output a URL that you need to open in your browser. After authorizing the application, you'll be redirected to a URL that contains an authorization code. This will try to load localhost and may look like it didn't work. That is expected - you need to copy the code from the URL.

### Step 2: Exchange the Code for Tokens

From the redirect URL, extract the `code` parameter (e.g., `http://localhost:8000/authorization?state=&code=EXTRACT_THIS_CODE&scope=read,activity:read,activity:write`), then:

```bash
# Exchange the code for tokens
python -m strava_cta.authorize_strava --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --code EXTRACTED_CODE
```

This will return your access token, refresh token, and expiration time. **Note that the authorization code is single-use only**. If you need to reauthorize, you'll need to generate a new authorization URL and get a new code.

Once you have obtained these tokens, set them as environment variables or GitHub secrets according to your deployment method.

### Important Note on Token Handling

- The authorization code from Step 1 is **single-use only** and will expire after a short time
- The refresh token is used to obtain new access tokens when they expire
- Access tokens are valid for a limited time (usually a few hours)
- When running in GitHub Actions, tokens are automatically set as environment variables for subsequent steps

## Development

### Setting up for development

```bash
# Install dependencies
uv sync
```

### Project Structure

- `strava_cta/`: Main package directory
  - `check_activities.py`: Core functionality for checking and updating activities
  - `authorize_strava.py`: Handles the Strava OAuth flow (generate URL, exchange code, refresh tokens)
- `main.py`: CLI entry point
- `cta.txt`: Example CTA content
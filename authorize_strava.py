#!/usr/bin/env python3
"""
Strava token refresh script using stravalib.

This script implements Step 3 from the stravalib documentation:
https://stravalib.readthedocs.io/en/latest/get-started/authenticate-with-strava.html#step-3-refresh-your-token

It refreshes a Strava access token and outputs the new tokens without writing to any files.
"""

import os
import sys
import argparse
import logging
from stravalib.client import Client

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def refresh_access_token(client_id, client_secret, refresh_token):
    """
    Refresh a Strava access token using the refresh token.
    
    Args:
        client_id (str): Strava API client ID
        client_secret (str): Strava API client secret
        refresh_token (str): Refresh token from previous authorization
        
    Returns:
        dict: Token response containing new access and refresh tokens
    """
    client = Client()
    
    try:
        # Following stravalib documentation for token refresh
        token_response = client.refresh_access_token(
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token
        )
        
        return token_response
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise

def main():
    """Refresh Strava API token."""
    parser = argparse.ArgumentParser(description='Refresh Strava API token')
    parser.add_argument('--client-id', help='Strava API client ID')
    parser.add_argument('--client-secret', help='Strava API client secret')
    parser.add_argument('--refresh-token', help='Strava API refresh token')
    # parser.add_argument('--code', help='Strava API authorization code')
    args = parser.parse_args()
    
    # Get required parameters from args or environment
    client_id = args.client_id or os.environ.get('STRAVA_CLIENT_ID')
    client_secret = args.client_secret or os.environ.get('STRAVA_CLIENT_SECRET')
    refresh_token = args.refresh_token or os.environ.get('STRAVA_REFRESH_TOKEN')
    # code = args.code or os.environ.get('STRAVA_CODE')

    # Validate required parameters
    missing_params = []
    if not client_id:
        missing_params.append("Strava Client ID (--client-id or STRAVA_CLIENT_ID)")
    if not client_secret:
        missing_params.append("Strava Client Secret (--client-secret or STRAVA_CLIENT_SECRET)")
    if not refresh_token:
        missing_params.append("Strava Refresh Token (--refresh-token or STRAVA_REFRESH_TOKEN)")
    # if not code:
    #     missing_params.append("Strava Authorization Code (--code or STRAVA_CODE)")
    
    if missing_params:
        for param in missing_params:
            logger.error(f"Missing required parameter: {param}")
        return 1
    
    try:
        logger.info("Refreshing Strava API token...")
        tokens = refresh_access_token(client_id, client_secret, refresh_token)
        
        # Output token information
        logger.info(f"Token successfully refreshed. Expires at: {tokens['expires_at']}")
        
        # Extract the tokens from the response
        access_token = tokens['access_token']
        new_refresh_token = tokens['refresh_token']
        expires_at = tokens['expires_at']
        
        # Check if running in GitHub Actions
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            # For GitHub Actions, use the environment file approach
            github_env = os.environ.get('GITHUB_ENV')
            if github_env:
                with open(github_env, 'a') as f:
                    f.write(f"STRAVA_REFRESH_TOKEN={new_refresh_token}\n")
                    f.write(f"STRAVA_ACCESS_TOKEN={access_token}\n")
                    f.write(f"STRAVA_TOKEN_EXPIRES_AT={expires_at}\n")
                logger.info("Set Strava tokens in GitHub Actions environment")
            else:
                # Fallback to echo approach for GitHub Actions
                print(f"STRAVA_REFRESH_TOKEN={new_refresh_token}")
                print(f"STRAVA_ACCESS_TOKEN={access_token}")
                print(f"STRAVA_TOKEN_EXPIRES_AT={expires_at}")
        else:
            # For local use, just print the tokens for capture
            print(f"STRAVA_REFRESH_TOKEN={new_refresh_token}")
            print(f"STRAVA_ACCESS_TOKEN={access_token}")
            print(f"STRAVA_TOKEN_EXPIRES_AT={expires_at}")
            
        logger.info("Token refresh completed successfully")
        
        return 0
    except Exception as e:
        logger.error(f"Error in token refresh process: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())

if __name__ == '__main__':
    sys.exit(main())

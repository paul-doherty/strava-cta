#!/usr/bin/env python3
"""
Strava authorization script using stravalib.

This script implements all steps from the stravalib documentation:
https://stravalib.readthedocs.io/en/latest/get-started/authenticate-with-strava.html

It handles:
1. Creating an authorization URL
2. Exchanging the authorization code for tokens
3. Refreshing existing tokens
"""

import os
import sys
import argparse
import logging

# Disable logging for libraries that might log sensitive information
logging.getLogger("stravalib").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)

# Set up logging for this script
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

from stravalib.client import Client


def generate_authorization_url(client_id):
    """
    Generate the authorization URL to obtain user permission.

    Args:
        client_id (str): Strava API client ID

    Returns:
        str: Authorization URL
    """
    client = Client()

    # Generate authorization URL with requested scopes
    url = client.authorization_url(
        client_id=client_id,
        redirect_uri="http://localhost:8000/authorization",
        scope=["read", "activity:read_all", "activity:write"],
    )

    return url


def exchange_code_for_token(client_id, client_secret, code):
    """
    Exchange authorization code for access and refresh tokens.

    Args:
        client_id (str): Strava API client ID
        client_secret (str): Strava API client secret
        code (str): Authorization code from redirect

    Returns:
        dict: Token response containing access_token, refresh_token, and expires_at
    """
    client = Client()

    try:
        token_response = client.exchange_code_for_token(
            client_id=client_id, client_secret=client_secret, code=code
        )

        return token_response
    except Exception as e:
        logger.error(f"Error exchanging code for token: {e}")
        raise


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
        token_response = client.refresh_access_token(
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
        )

        return token_response
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise


def handle_token_response(token_response):
    """
    Process and output the token response.

    Args:
        token_response (dict): Token response from Strava API

    Returns:
        None
    """
    # Extract tokens
    access_token = token_response["access_token"]
    refresh_token = token_response["refresh_token"]
    expires_at = token_response["expires_at"]

    # If in GitHub Actions, also write to GITHUB_ENV
    github_env = os.environ.get("GITHUB_ENV")
    if os.environ.get("GITHUB_ACTIONS") == "true" and github_env:
        with open(github_env, "a") as f:
            f.write(f"STRAVA_REFRESH_TOKEN={refresh_token}\n")
            f.write(f"STRAVA_ACCESS_TOKEN={access_token}\n")
            f.write(f"STRAVA_TOKEN_EXPIRES_AT={expires_at}\n")
        logger.info("Set Strava tokens in GitHub Actions environment")
    else:
        print(f"STRAVA_REFRESH_TOKEN={refresh_token}")
        print(f"STRAVA_ACCESS_TOKEN={access_token}")
        print(f"STRAVA_TOKEN_EXPIRES_AT={expires_at}")

    logger.info(f"Access token expires at: {expires_at}")
    logger.info("Token operation completed successfully")


def main():
    """Execute the Strava authorization process."""
    parser = argparse.ArgumentParser(description="Strava API Authorization Tool")
    parser.add_argument("--client-id", help="Strava API client ID")
    parser.add_argument("--client-secret", help="Strava API client secret")
    # parser.add_argument(
        # "--refresh-token", help="Strava API refresh token (for refresh flow)"
    # )
    parser.add_argument(
        "--code", help="Authorization code from redirect (for exchange flow)"
    )
    args = parser.parse_args()

    # Get client ID and secret from args or environment
    client_id = args.client_id or os.environ.get("STRAVA_CLIENT_ID")
    client_secret = args.client_secret or os.environ.get("STRAVA_CLIENT_SECRET")
    code = args.code or os.environ.get("STRAVA_CODE")

    if not client_id:
        logger.error(
            "Missing required parameter: Strava Client ID (--client-id or STRAVA_CLIENT_ID)"
        )
        return 1

    if not client_secret:
        logger.error(
            "Missing required parameter: Strava Client Secret (--client-secret or STRAVA_CLIENT_SECRET)"
        )
        return 1

    try:
        # Generate authorization URL if no code is provided
        if code is None:
            # If we don't have a code, generate an authorization URL
            url = generate_authorization_url(client_id)
            print(f"Authorization URL: {url}")
            logger.info("Copy this URL into your browser to authorize the application")
            return 0
        
        # Exchange authorization code for tokens if code is provided
        logger.info("Exchanging authorization code for tokens...")
        token_response = exchange_code_for_token(
            client_id, client_secret, code
        )
        handle_token_response(token_response)
        return 0

    except Exception as e:
        logger.error(f"Error in Strava authorization process: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

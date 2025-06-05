import argparse
import os
import sys
import datetime
import logging

from stravalib import Client

logger = logging.getLogger(__name__)

# Disable logging for libraries that might log sensitive information
logging.getLogger("stravalib").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)

class Cta:
    def get_cta_content(self):
        """
        Read the CTA content from the file.

        Returns:
            str: The content of the CTA file
        """
        try:
            with open("cta.txt", "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            logger.error("CTA file not found at cta.txt")
            return ""


class StravaActivityChecker:
    def __init__(self):
        """
        Initialize the StravaActivityChecker.
        This class is responsible for checking and updating Strava activities with a call-to-action (CTA).
        """
        self.cta = Cta().get_cta_content()

    def contains_cta(self, activity):
        return self.cta in activity.description

    def prepend_cta(self, activity):
        """
        Prepend the CTA content to the activity description if it doesn't already contain it.

        Args:
            activity (str): The activity description

        Returns:
            str: Updated activity description with CTA prepended
        """
        activity.description = f"{self.cta}\n\n{activity.description}"
        return activity

    def update_activities(self, access_token, refresh_token=None, token_expires=None):
        """
        Fetch activities from Strava using the provided access token.

        Args:
            access_token (str): Strava API access token
            refresh_token (str, optional): Strava API refresh token
            token_expires (str, optional): Strava API token expiration time

        Returns:
            list: List of activities
        """
        client = Client(
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires=token_expires,
        )
        today_midnight_utc = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        
        count = 0
        try:
            for activity in client.get_activities(after=today_midnight_utc):
                count += 1
                detailed_activity = client.get_activity(activity.id)
                if not self.contains_cta(detailed_activity):
                    detailed_activity = self.prepend_cta(detailed_activity)
                    client.update_activity(
                        activity_id=detailed_activity.id,
                        description=detailed_activity.description,
                    )
                    print(f"Activity {detailed_activity.id} updated.")
                else:
                    print(f"Activity {detailed_activity.id} already contains CTA content.")
        except Exception as e:
            logger.error(f"Error processing activities: {e}")
            return None
        logger.info(f"Checked {count} activities for CTA content.")
        
        access_token = client.access_token
        refresh_token = client.refresh_token
        token_expires = client.token_expires
        return (access_token, refresh_token, token_expires)


def main():
    """Execute the Strava authorization process."""
    parser = argparse.ArgumentParser(description="Strava Activity Checker Tool")
    parser.add_argument(
        "--refresh-token", help="Strava API refresh token (for refresh flow)"
    )
    parser.add_argument(
        "--token-expires", help="Strava API token expiration time", type=float
    )
    parser.add_argument("--access-token", help="Strava API access token")
    args = parser.parse_args()

    access_token = args.access_token or os.environ.get("STRAVA_ACCESS_TOKEN")
    refresh_token = args.refresh_token or os.environ.get("STRAVA_REFRESH_TOKEN")
    token_expires = args.token_expires or os.environ.get("STRAVA_TOKEN_EXPIRES_AT")
    
    if not access_token:
        logger.error("Access token is required. Please provide it via --access-token or STRAVA_ACCESS_TOKEN environment variable.")
        return 1
    if not refresh_token:
        logger.error("Refresh token is required. Please provide it via --refresh-token or STRAVA_REFRESH_TOKEN environment variable.")
        return 1
    if not token_expires:
        logger.error("Token expiration time is required. Please provide it via --token-expires or STRAVA_TOKEN_EXPIRES_AT environment variable.")
        return 1

    cta = Cta().get_cta_content()
    if not cta:
        logger.error(
            "CTA content is empty. Please ensure cta.txt exists and contains valid content."
        )
        return 1

    checker = StravaActivityChecker()
    updated_tokens = checker.update_activities(access_token, refresh_token, float(token_expires))
    
    if updated_tokens:
        gh_access_token, gh_refresh_token, gh_token_expires = updated_tokens
        # Update GitHub secrets if running in GitHub Actions
        if os.environ.get("GITHUB_ACTIONS") == "true":
            os.system(f"gh secret set STRAVA_ACCESS_TOKEN {gh_access_token}")
            os.system(f"gh secret set STRAVA_REFRESH_TOKEN {gh_refresh_token}")
            os.system(f"gh secret set STRAVA_TOKEN_EXPIRES_AT {gh_token_expires}")
            logger.info("Updated GitHub secrets with new Strava tokens.")


if __name__ == "__main__":
    logging.basicConfig(filename='cta.log', level=logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
    sys.exit(main())

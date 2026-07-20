# modules/updater.py
import logging
import requests
import subprocess
import sys
import os

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

GITHUB_REPO_OWNER = "mahdikh007"
GITHUB_REPO_NAME = "attack-surface"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/releases/latest"

def get_latest_version_from_github() -> str | None:
    """Fetches the latest release version from GitHub."""
    try:
        response = requests.get(GITHUB_API_URL, timeout=5)
        response.raise_for_status() # Raise an exception for HTTP errors
        release_info = response.json()
        latest_tag = release_info.get("tag_name")
        if latest_tag and latest_tag.startswith("v"):
            return latest_tag[1:] # Remove 'v' prefix
        return latest_tag
    except requests.exceptions.RequestException as e:
        logging.warning("Could not check for updates on GitHub: %s", e)
        return None
    except Exception as e:
        logging.error("An unexpected error occurred while checking for updates: %s", e)
        return None

def is_update_available(current_version: str, latest_version: str) -> bool:
    """Compares current version with the latest available version."""
    def parse_version(version_str: str):
        try:
            return tuple(map(int, version_str.split('.')))
        except ValueError:
            return (0,) # Fallback for invalid version strings

    current = parse_version(current_version)
    latest = parse_version(latest_version)

    return latest > current

def perform_update():
    """Performs a git pull to update the repository."""
    logging.info("Attempting to update via Git...")
    try:
        # Check if we are in a git repository
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], check=True, capture_output=True)
        
        # Ensure we are on the main branch (or the branch user is on)
        current_branch_cmd = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
        current_branch = current_branch_cmd.stdout.strip()
        
        logging.info("Running 'git pull origin %s'...", current_branch)
        result = subprocess.run(["git", "pull", "origin", current_branch], capture_output=True, text=True, check=True)
        logging.info("Git pull output:\n%s", result.stdout)
        if "Already up to date." in result.stdout or "up to date" in result.stdout:
            logging.info("Already at the latest version.")
        else:
            logging.info("Update successful! Please restart the tool.")
            sys.exit(0) # Exit to force user to restart with new code

    except subprocess.CalledProcessError as e:
        logging.error("Git update failed: %s - %s", e, e.stderr)
    except FileNotFoundError:
        logging.warning("Git command not found. Cannot perform auto-update.")
    except Exception as e:
        logging.error("An unexpected error occurred during Git update: %s", e)


def check_for_updates(current_version: str):
    """Main function to check and offer updates."""
    logging.info("Checking for updates (current version: v%s)...", current_version)
    latest_version = get_latest_version_from_github()

    if latest_version:
        if is_update_available(current_version, latest_version):
            logging.warning("A new version (v%s) is available! Your current version is v%s.", latest_version, current_version)
            # In a non-interactive script, you might automatically update.
            # For now, let's just log and offer.
            # if input("Do you want to update now? (y/N): ").lower() == 'y':
            perform_update()
            # else:
            #     logging.info("Skipping update.")
        else:
            logging.info("You are running the latest version (v%s).", current_version)
    else:
        logging.warning("Could not determine the latest version from GitHub.")

# Example Usage (for testing)
if __name__ == "__main__":
    check_for_updates("0.1.0") # Test with a lower version
    # check_for_updates("99.9.9") # Test with a higher version


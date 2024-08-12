import subprocess
import sys
from datetime import datetime

def run_command(command):
    """Run a shell command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return result.stdout.strip()

def create_snapshot():
    """Create a time-based snapshot of the current state."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    snapshot_branch = f"snapshot-{timestamp}"
    run_command(f"git checkout -b {snapshot_branch}")
    run_command(f"git add .")
    run_command(f"git commit -m 'Snapshot at {timestamp}'")
    run_command(f"git checkout main")
    return snapshot_branch

def retract_patch(patch_id):
    """Retract a specific patch by its ID using advanced methodology."""
    # Create a snapshot before retraction
    snapshot_branch = create_snapshot()

    # Create a new branch for the retraction
    retraction_branch = f"retract-{patch_id}"
    run_command(f"git checkout -b {retraction_branch}")

    # Revert the patch
    run_command(f"git revert {patch_id}")

    # Commit the retraction
    run_command(f"git commit -m 'Retract patch {patch_id}'")

    # Check out the main branch
    run_command("git checkout main")

    # Merge the retraction into the main branch
    run_command(f"git merge {retraction_branch}")

    # Delete the retraction branch
    run_command(f"git branch -d {retraction_branch}")

    # Optionally, keep the snapshot branch for future reference
    print(f"Snapshot created: {snapshot_branch}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python retract_patch.py <patch_id>")
        sys.exit(1)

    patch_id = sys.argv[1]
    retract_patch(patch_id)
    print(f"Patch {patch_id} retracted successfully.")

if __name__ == "__main__":
    main()

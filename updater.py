import os
import sys
import requests
import shutil
import zipfile
import tempfile

REPO_VERSION_URL = "https://raw.githubusercontent.com/diobrando2004/Project2/main/version.txt"
REPO_ZIP_URL     = "https://github.com/diobrando2004/Project2/archive/refs/heads/main.zip"
MODEL_FILENAME   = "adaptive_rf_malware.pkl"
TARGET_FILES     = ["app.py", "version.txt"]

# Determine the folder where app.py (or app.exe) lives
if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(__file__)

def get_current_version():
    """Read local version.txt; returns '0.0.0' on any failure."""
    try:
        path = os.path.join(app_dir, "version.txt")
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"

def get_remote_version():
    resp = requests.get(REPO_VERSION_URL, timeout=10)
    resp.raise_for_status()
    return resp.text.strip()

def is_newer(remote, local):
    return tuple(map(int, remote.split("."))) > tuple(map(int, local.split(".")))

def download_model(version):
    """Download the model from your GitHub Releases and atomically replace."""
    model_url = f"https://github.com/diobrando2004/Project2/releases/download/v{version}/{MODEL_FILENAME}"
    target    = os.path.join(app_dir, MODEL_FILENAME)
    tmp       = target + ".tmp"

    print(f"Downloading model from {model_url}")
    try:
        r = requests.get(model_url, stream=True, timeout=30)
        r.raise_for_status()
        with open(tmp, "wb") as fw:
            shutil.copyfileobj(r.raw, fw)
        os.replace(tmp, target)
        print("Model updated.")
    except Exception as e:
        print(f"Model download failed: {e}")
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

def download_and_extract():
    """Fetch the repo zip, extract to temp, and return the root folder."""
    print("Downloading full repo for code update…")
    r = requests.get(REPO_ZIP_URL, timeout=30)
    r.raise_for_status()

    temp_dir = tempfile.mkdtemp(prefix="updater_")
    zip_path = os.path.join(temp_dir, "repo.zip")
    with open(zip_path, "wb") as fzip:
        fzip.write(r.content)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)

    return os.path.join(temp_dir, "Project2-main"), temp_dir

def update_files(src_dir):
    for fname in TARGET_FILES:
        src = os.path.join(src_dir, fname)
        dst = os.path.join(app_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"  → Updated {fname}")
        else:
            print(f"  ! Skipped {fname} (not found in repo)")

def main():
    try:
        local  = get_current_version()
        remote = get_remote_version()
        print(f"Local version: {local} — Remote version: {remote}")

        if is_newer(remote, local):
            print("New version detected. Updating…")
            repo_root, workdir = download_and_extract()
            try:
                update_files(repo_root)
                download_model(remote)
                print("Update succeeded.")
                sys.exit(0)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("You’re already on the latest version.")
            sys.exit(2)

    except Exception as e:
        print(f"Update process failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

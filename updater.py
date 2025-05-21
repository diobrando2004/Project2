import os
import sys
import requests
import shutil
import zipfile
import tempfile
import subprocess
import time
REPO_VERSION_URL = "https://raw.githubusercontent.com/diobrando2004/Project2/main/version.txt"
#REPO_ZIP_URL     = "https://github.com/diobrando2004/Project2/archive/refs/heads/main.zip"
MODEL_FILENAME   = "model.dat"
TARGET_FILES     = ["app.py", "version.txt"]
ZIP_DOWNLOAD_URL = "https://github.com/diobrando2004/Project2/releases/download/v{version}/resources.zip"

if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(__file__)

def get_current_version():
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

"""
def download_model(version):
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
"""
""""
def download_and_extract():
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
"""
def download_and_extract_zip(version):
    zip_url = ZIP_DOWNLOAD_URL.format(version=version)
    print(f"Downloading update zip from {zip_url}")

    temp_dir = tempfile.mkdtemp(prefix="updater_")
    zip_path = os.path.join(temp_dir, "update.zip")

    try:
        r = requests.get(zip_url, timeout=30)
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            f.write(r.content)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        os.remove(zip_path) 
        print("Extracted and removed update zip.")
        version_file_path = os.path.join(app_dir, "version.txt")
        with open(version_file_path, "w") as fver:
            fver.write(version)
        return temp_dir
    except Exception as e:
        print(f"Failed to download or extract zip: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

def replace_files(src_dir):
    print("Replacing current files with new ones…")
    for root, dirs, files in os.walk(src_dir):
        rel_path = os.path.relpath(root, src_dir)
        target_dir = os.path.join(app_dir, rel_path)

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        for fname in files:
            src_file = os.path.join(root, fname)
            dst_file = os.path.join(target_dir, fname)
            shutil.copy2(src_file, dst_file)
            print(f"  → Replaced {os.path.relpath(dst_file, app_dir)}")

""""
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
"""

def launch_new_exe():
    exe_path = os.path.join(app_dir, "app.exe")
    try:
        subprocess.Popen([exe_path])
    except Exception as e:
        print(f"Failed to launch the new executable: {e}")

def main():
    try:
        local_version = get_current_version()
        remote_version = get_remote_version()
        print(f"Local version: {local_version} — Remote version: {remote_version}")

        if is_newer(remote_version, local_version):
            print("New version detected. Updating…")
            extracted_dir = download_and_extract_zip(remote_version)
            try:
                replace_files(extracted_dir)
                print("Update completed successfully.")
                time.sleep(4)
                launch_new_exe()
                sys.exit(0)
            finally:
                shutil.rmtree(extracted_dir, ignore_errors=True)
        else:
            print("You're already on the latest version.")
            time.sleep(4)
            launch_new_exe()
            sys.exit(2)
    except Exception as e:
        print(f"Update failed: {e}")
        time.sleep(4)
        sys.exit(1)

if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import joblib
import os
import sys
import pefile
import pandas as pd
import array
import math
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor

if getattr(sys, 'frozen', False):  
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(base_path, "adaptive_rf_malware.pkl")

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    model = None
    print(f"Error loading model: {e}")


def is_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        return True
    except pefile.PEFormatError:
        return False 
    except Exception as e:
        print(f"Error checking {file_path}: {e}")
        return False

#entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

#resources
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

#version information
def get_version_info(pe):
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          res['os'] = pe.VS_FIXEDFILEINFO.FileOS
          res['type'] = pe.VS_FIXEDFILEINFO.FileType
          res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          res['signature'] = pe.VS_FIXEDFILEINFO.Signature
          res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    
    #res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit

    res['SectionsNb'] = len(pe.sections)
    entropy = [section.get_entropy() for section in pe.sections]
    res['SectionsMeanEntropy'] = sum(entropy)/float(len((entropy)))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len((raw_sizes)))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0
    resources= get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources)> 0:
        entropy = [resource[0] for resource in resources]
        res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = [resource[1] for resource in resources]
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res



def check_malware():
    def scan():
        if not model:
            root.after(0, lambda: result_label.config(text=" Error: Model not loaded", fg="red"))
            return

        file_path = file_entry.get()
        if not file_path:
            root.after(0, lambda: result_label.config(text=" Please select a file.", fg="orange"))
            return

        if not is_pe_file(file_path):
            root.after(0, lambda: result_label.config(text=" Error: Not a valid PE file.", fg="red"))
            return

        try:
            features = extract_infos(file_path)
            if features is None:
                root.after(0, lambda: result_label.config(text=" Error: Feature extraction failed.", fg="red"))
                return

            res = pd.DataFrame([features])
            res["is_size_zero"] = (res["SizeOfImage"] == 0).astype(int)
            min_size = 4096
            res["SizeOfImage"] = res["SizeOfImage"].replace(0, min_size)

            res["SizeOfHeaders"] = res["SizeOfHeaders"] / res["SizeOfImage"]
            res["CheckSum"] = res["CheckSum"] / res["SizeOfImage"]
            res["SectionsMeanRawsize"] = res["SectionsMeanRawsize"] / res["SizeOfImage"]
            res["SectionsMinRawsize"] = res["SectionsMinRawsize"] / res["SizeOfImage"]
            res["SectionsMaxRawsize"] = res["SectionsMaxRawsize"] / res["SizeOfImage"]
            res["SectionsMeanVirtualsize"] = res["SectionsMeanVirtualsize"] / res["SizeOfImage"]
            res["SectionsMinVirtualsize"] = res["SectionsMinVirtualsize"] / res["SizeOfImage"]
            res["SectionMaxVirtualsize"] = res["SectionMaxVirtualsize"] / res["SizeOfImage"]
            res["SizeOfCode"] = res["SizeOfCode"] / res["SizeOfImage"]
            res["SizeOfInitializedData"] = res["SizeOfInitializedData"] / res["SizeOfImage"]
            res["SizeOfUninitializedData"] = res["SizeOfUninitializedData"] / res["SizeOfImage"]
            res["ResourcesMeanSize"] = res["ResourcesMeanSize"] / res["SizeOfImage"]
            res["ResourcesMinSize"] = res["ResourcesMinSize"] / res["SizeOfImage"]
            res["ResourcesMaxSize"] = res["ResourcesMaxSize"] / res["SizeOfImage"]
            res = res.drop(columns='VersionInformationSize', axis=1)

            x_dict = res.iloc[0].to_dict()
            prediction = model.predict_one(x_dict)
            proba = model.predict_proba_one(x_dict)
            confidence = proba.get(prediction, 0) * 100
            result_text = "Malware Detected!" if prediction == 1 else "File is Safe."
            result_color = "red" if prediction == 1 else "green"

            root.after(0, lambda: result_label.config(
                text=f"{result_text}\nConfidence: {confidence:.2f}%", fg=result_color
            ))

        except Exception as e:
            root.after(0, lambda: result_label.config(text=f"Error: {e}", fg="red"))

    scan_thread = threading.Thread(target=scan)
    scan_thread.start()


def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)


def process_file(file_path):
    if not is_pe_file(file_path):
        return None

    try:
        features = extract_infos(file_path)
        if features is None:
            return None

        res = pd.DataFrame([features])
        res["is_size_zero"] = (res["SizeOfImage"] == 0).astype(int)
        min_size = 4096
        res["SizeOfImage"] = res["SizeOfImage"].replace(0, min_size)

        # Normalize features
        for col in [
            "SizeOfHeaders", "CheckSum", "SectionsMeanRawsize", "SectionsMinRawsize",
            "SectionsMaxRawsize", "SectionsMeanVirtualsize", "SectionsMinVirtualsize",
            "SectionMaxVirtualsize", "SizeOfCode", "SizeOfInitializedData",
            "SizeOfUninitializedData", "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize"
        ]:
            res[col] = res[col] / res["SizeOfImage"]

        res = res.drop(columns='VersionInformationSize', axis=1)
        x_dict = res.iloc[0].to_dict()

        prediction = model.predict_one(x_dict)
        proba = model.predict_proba_one(x_dict)
        confidence = proba.get(prediction, 0) * 100
        result_text = "Malware Detected!" if prediction == 1 else "File is Safe."

        return {
            "text": f"{file_path}\n {result_text} (Confidence: {confidence:.2f}%)\n",
            "features": x_dict,
            "predicted": prediction,
            "path": file_path
        }

    except Exception as e:
        return {
            "text": f"{file_path}\n Error - {e}\n",
            "features": None,
            "predicted": None,
            "path": file_path
        }

results_data = []

def scan_directory():
    def scan():
        global results_data
        if not model:
            messagebox.showerror("Error", "Model not loaded.")
            return

        dir_path = filedialog.askdirectory()
        if not dir_path:
            messagebox.showwarning("Warning", "Please select a directory.")
            return

        results_text.config(state=tk.NORMAL)
        results_text.delete(1.0, tk.END)  
        results_text.insert(tk.END, f"Scanning directory: {dir_path}\n\n")
        progress_bar.start()

        file_paths = [os.path.join(root, file) for root, _, files in os.walk(dir_path) for file in files]
        results_data = []  # Reset before scan
        display_lines = []
        malware_count = 0
        benign_count = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            scan_results = list(executor.map(process_file, file_paths))

        for result in scan_results:
            if result:
                display_lines.append(result["text"])
                results_data.append(result)
                if "Malware Detected!" in result["text"]:
                    malware_count += 1
                else:
                    benign_count += 1

        progress_bar.stop()

        if display_lines:
            results_text.insert(tk.END, "\n".join(display_lines))
        else:
            results_text.insert(tk.END, "No PE files found in the selected directory.")

        results_text.insert(tk.END, f"\n\nTotal Malware: {malware_count}\nTotal Benign Files: {benign_count}\n")
        results_text.config(state=tk.DISABLED)

    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

def correct_selected(true_label):
    try:
        index = int(results_text.index(tk.INSERT).split('.')[0]) - 1  # Line number - 1
        line_count = 0

        for i, item in enumerate(results_data):
            lines = item["text"].count('\n') + 1
            line_count += lines
            if index < line_count:
                if item["features"] is None:
                    messagebox.showwarning("Warning", "No features available for correction.")
                    return
                model.learn_one(item["features"], true_label)
                messagebox.showinfo("Correction", f"Model updated for:\n{item['path']}")
                
                # Optional: Save updated model
                return

        messagebox.showwarning("Warning", "Could not locate selection.")
    except Exception as e:
        messagebox.showerror("Error", f"Correction failed: {e}")

def correct_all(label):
    if not model:
        messagebox.showerror("Error", "Model not loaded.")
        return

    corrected = 0
    for entry in results_data:
        features = entry.get("features")
        if features:
            try:
                model.learn_one(features, label)
                corrected += 1
            except Exception as e:
                print(f"Failed to correct entry: {entry.get('path')} - {e}")
    
    messagebox.showinfo("Correction Done", f"{corrected} entries updated as {'Malware' if label else 'Benign'}.")

def run_updater():
    app_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__))
    updater_path = os.path.join(app_dir, "updater.py")
    subprocess.Popen(["python", updater_path])

root = tk.Tk()
root.title("Malware Detector")
root.geometry("600x400")
root.configure(bg="#2c3e50")

result_label = tk.Label(root, text="", font=("Arial", 12), fg="black")
result_label.pack(pady=10) 

style = ttk.Style()
style.configure("TButton", font=("Arial", 10), padding=5)
style.configure("TLabel", background="#2c3e50", foreground="white", font=("Arial", 12))

frame = tk.Frame(root, bg="#2c3e50")
frame.pack(pady=0)

tk.Label(frame, text="Select a file to check for malware:", bg="#2c3e50", fg="white", font=("Arial", 12)).pack()
file_entry = tk.Entry(frame, width=50)
file_entry.pack(pady=5)
ttk.Button(frame, text="Browse", command=browse_file).pack(pady=5)
ttk.Button(frame, text="Check Single File", command=check_malware, style="TButton").pack(pady=10)
ttk.Button(frame, text="Scan Directory", command=scan_directory, style="TButton").pack(pady=10)

progress_bar = ttk.Progressbar(root, mode="indeterminate", length=250)
progress_bar.pack(pady=10)

results_frame = tk.Frame(root)
results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

results_text = tk.Text(results_frame, height=10, wrap="word", font=("Arial", 10))
results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
results_text.config(state=tk.DISABLED)  
ttk.Button(root, text="Report Selected as Malware", command=lambda: correct_selected(1)).pack(pady=2)
ttk.Button(root, text="Report Selected as Benign", command=lambda: correct_selected(0)).pack(pady=2)
ttk.Button(frame, text="Report All as Safe", command=lambda: correct_all(0)).pack(pady=5)
ttk.Button(frame, text="Report All as Malware", command=lambda: correct_all(1)).pack(pady=5)
ttk.Button(frame, text="Check for Updates", command=run_updater).pack(pady=5)
scrollbar = ttk.Scrollbar(results_frame, command=results_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


root.mainloop()
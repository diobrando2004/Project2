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
import sklearn
from concurrent.futures import ThreadPoolExecutor

if getattr(sys, 'frozen', False):  
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(base_path, "random_forest_malwareBig.pkl")

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
        print(f"Error {file_path}: {e}")
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
        result_color="green"
        result_text = process_file(file_path)
        if  "Malware Detected!" in result_text: result_color="red"
        root.after(0, lambda: result_label.config(
            text=f"{result_text}", fg=result_color
        ))
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
        #res["SizeOfOptionalHeader"] = res["SizeOfOptionalHeader"]
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
        #res["SizeOfHeapReserve"] = res["SizeOfHeapReserve"] 
        #res["SizeOfHeapCommit"] = res["SizeOfHeapCommit"]
        #res["SizeOfStackReserve"] = res["SizeOfStackReserve"] 
        # res["SizeOfStackCommit"] = res["SizeOfStackCommit"]
        res["ResourcesMeanSize"] = res["ResourcesMeanSize"] / res["SizeOfImage"]
        res["ResourcesMinSize"] = res["ResourcesMinSize"] / res["SizeOfImage"]
        res["ResourcesMaxSize"] = res["ResourcesMaxSize"] / res["SizeOfImage"]

        prediction = model.predict(res)
        probability = model.predict_proba(res)
        result = " Malware Detected!" if prediction[0] == 1 else " File is Safe."
        confidence = probability[0][prediction[0]] * 100

        return f"{file_path}\n{result} (Confidence: {confidence:.2f}%)\n"

    except Exception as e:
        return f"{file_path}\n Error - {e}\n"



def scan_directory():
    def scan():
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
        results = []
        malware_count = 0
        benign_count = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            scan_results = list(executor.map(process_file, file_paths))

        for result in scan_results:
            if result:
                results.append(result)
                if "Malware Detected!" in result:
                    malware_count += 1
                else:
                    benign_count += 1

        progress_bar.stop()

        if results:
            results_text.insert(tk.END, "\n".join(results))
        else:
            results_text.insert(tk.END, "No PE files found in the selected directory.")

        results_text.insert(tk.END, f"\n\nTotal Malware: {malware_count}\nTotal Benign Files: {benign_count}\n")
        results_text.config(state=tk.DISABLED)

    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

root = tk.Tk()
root.title("Malware Detector")
root.geometry("600x400")
root.configure(bg="#2c3e50")

result_label = tk.Label(root, text="", font=("Arial", 12), fg="black")
result_label.pack(pady=10) 

style = ttk.Style()
style.configure("TButton", font=("Arial", 10), padding=5)


frame = tk.Frame(root, bg="#2c3e50")
frame.pack(pady=20)

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

scrollbar = ttk.Scrollbar(results_frame, command=results_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
results_text.config(yscrollcommand=scrollbar.set)

root.mainloop()
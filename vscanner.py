import os
import json
import subprocess
from datetime import datetime  
import time

# Define the path to the extracted CVE directory
CVE_DIR = input('enter path to "CVEs" directory:') 

def get_installed_software():
    """
    Get a list of installed software and their versions on the system.
    This implementation is for Debian-based systems using dpkg.
    Change the implementation if you're using a different system.
    """
    print("Fetching installed software using dpkg...")
    software_list = []
    try:
        result = subprocess.run(['dpkg-query', '-W', '-f=${Package} ${Version}\n'], 
                                stdout=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if line.strip():
                package, version = line.strip().split(maxsplit=1)
                software_list.append({"product": package, "version": version})
        print(f"Found {len(software_list)} installed software packages.")
    except Exception as e:
        print(f"Error getting installed software: {e}")
    
    return software_list

def find_cves():
    # Get the list of installed software
    INSTALLED_SOFTWARE = get_installed_software()
    time.sleep(4)
    vulnerabilities_found = False  

    
    for year_dir in os.listdir(CVE_DIR):
        year_path = os.path.join(CVE_DIR, year_dir)
        if os.path.isdir(year_path):
            print(f"\nScanning for known CVEs from {year_dir}...")
            #  format "{number}xxx"
            for subdir in os.listdir(year_path):
                subdir_path = os.path.join(year_path, subdir)
                if os.path.isdir(subdir_path) and subdir.endswith("xxx"):
                    print(f"Processing subdirectory: {subdir}")
                    for cve_file in os.listdir(subdir_path):
                        cve_path = os.path.join(subdir_path, cve_file)
                        if os.path.isfile(cve_path) and cve_file.endswith(".json"):
                            #JSON file read 
                            with open(cve_path, "r", encoding="utf-8") as f:
                                try:
                                    cve_data = json.load(f)
                                except json.JSONDecodeError:
                                    print(f"Error reading JSON file: {cve_path}")
                                    continue

                            
                            cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
                            cna = cve_data.get("containers", {}).get("cna", {})
                            title = cna.get("title", "")
                            affected = cna.get("affected", [])

                            # compare to software installed locally 
                            for item in affected:
                                product = item.get("product", "")
                                versions = item.get("versions", [])
                                for version_info in versions:
                                    version = version_info.get("version", "")
                                    for software in INSTALLED_SOFTWARE:
                                        if (
                                            software["product"].lower() == product.lower()
                                            and software["version"] == version
                                        ):
                                            print(
                                                f"Vulnerability found: {title} in {cve_id}"
                                            )
                                            vulnerabilities_found = True  

    
    if not vulnerabilities_found:
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"No vulnerabilities found for localhost [{current_date}]")

    print("\nCVE scan completed.")

if __name__ == "__main__":
    print("Starting CVE vulnerability scan...")
    find_cves()

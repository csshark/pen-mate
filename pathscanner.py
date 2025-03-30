import requests
import concurrent.futures
import os

def check_path(url, path, headers=None):
    full_url = f"{url}/{path}"
    try:
        response = requests.get(full_url, headers=headers)
        if response.status_code == 200:  # Page exists
            print(f"Found: {full_url} (Status: {response.status_code})")
            return full_url
        elif response.status_code == 403:  # Forbidden
            print(f"Found (Forbidden): {full_url} (Status: {response.status_code})")
            return full_url
        elif response.status_code == 301 or response.status_code == 302:  # Redirect
            print(f"Found (Redirect): {full_url} (Status: {response.status_code}) -> {response.headers['Location']}")
            return full_url
    except Exception as e:
        print(f"Error checking {full_url}: {e}")
    return None

def path_scan(url, wordlist, headers=None, recursive=False):
    print(f"Scanning paths on {url}...")
    found_paths = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_path, url, path, headers) for path in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_paths.append(result)
                if recursive:
                    # subdirectories scan rec 
                    sub_wordlist = [os.path.join(result, path) for path in wordlist]
                    found_paths.extend(path_scan(url, sub_wordlist, headers, recursive))

    return found_paths


def load_wordlist(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    url = input("Enter the target URL (e.g., https://example.com): ").strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    wordlist_file = input("Enter the path to the wordlist file (e.g., wordlist.txt): ").strip()
    if not os.path.isfile(wordlist_file):
        print("Wordlist file not found!")
        return

    wordlist = load_wordlist(wordlist_file)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    found_paths = path_scan(url, wordlist, headers, recursive=True)

    if found_paths:
        print("\nFound paths:")
        for path in found_paths:
            print(f"- {path}")
    else:
        print("\nNo paths found.")

if __name__ == "__main__":
    main()

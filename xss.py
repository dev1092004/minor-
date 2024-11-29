import os
import requests
import threading

def load_payloads(file_path):
    """
    Load payloads from a given file. Each payload should be on a new line.
    """
    try:
        # Check if the file exists and is readable
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File does not exist: {file_path}")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"No read access to the file: {file_path}")
        
        # Read payloads from the file
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}")
        return []  # Return an empty list if there's an error


def test_xss(url, payload, results):
    """
    Test XSS vulnerability by injecting a single payload into the specified URL.
    Appends the result to the 'results' list.
    """
    try:
        # Send a GET request with the payload as a parameter
        response = requests.get(url, params={"query": payload}, timeout=5)  # Added timeout for robustness
        
        # Check if the payload is reflected in the response body
        if payload in response.text:
            results.append((payload, True))  # Vulnerability detected
        else:
            results.append((payload, False))  # No vulnerability detected
    except requests.exceptions.RequestException as e:
        results.append((payload, False))  # Mark no vulnerability if request fails
        print(f"Error making request for payload '{payload}': {e}")


def test_payloads_concurrently(url, payloads):
    """
    Run XSS tests concurrently using multiple threads.
    """
    threads = []
    results = []  # This will store the results of each payload test

    for payload in payloads:
        thread = threading.Thread(target=test_xss, args=(url, payload, results))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    return results


def summarize_results(results):
    """
    Summarize the results after testing all payloads.
    """
    summary = []
    for payload, is_vulnerable in results:
        status = "Vulnerable" if is_vulnerable else "Safe"
        summary.append(f"Payload: {payload} - {status}")
    
    return summary


def run_xss_scan(url, payload_file):
    """
    Orchestrates the XSS scan and returns results for the web application.
    """
    # Load payloads from the file
    payloads = load_payloads(payload_file)

    # Validate payloads
    if not payloads:
        return ["[!] No payloads loaded. Ensure the payload file exists and is readable."]
    
    # Run XSS tests concurrently
    results = test_payloads_concurrently(url, payloads)

    # Summarize results
    return summarize_results(results)


if __name__ == "__main__":
    # File containing payloads
    payload_file = r"C:\Users\DEVANSH\Downloads\FSCommand.txt"

    # Load payloads and validate
    payloads = load_payloads(payload_file)
    if not payloads:
        print("[!] No payloads loaded. Exiting.")
        exit(1)

    # Prompt user for URL
    target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not target_url.startswith(("http://", "https://")):
        print("Invalid URL. Please ensure it starts with http:// or https://.")
        exit(1)

    # Run XSS tests
    results = test_payloads_concurrently(target_url, payloads)

    # Print results
    print("\nResults:")
    for line in summarize_results(results):
        print(line)

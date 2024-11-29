import requests

# A basic list of known vulnerable software versions (you can extend this list with more software and versions)
VULNERABLE_SOFTWARE_VERSIONS = {
    "Apache": ["2.4.29", "2.4.38"],
    "nginx": ["1.14.0", "1.16.0"],
    "PHP": ["7.2.12", "7.3.0"],
    "Node.js": ["10.16.0", "12.0.0"],
}

def check_software_version(url):
    """
    Check the HTTP headers for server information and compare against known vulnerable versions.
    """
    try:
        # Send a GET request to the target URL
        response = requests.get(url)
        
        # Extract server information from the response headers
        server_info = response.headers.get("Server", "")
        x_powered_by = response.headers.get("X-Powered-By", "")
        
        # Check if we found any software version info in the headers
        software_versions = []
        
        if server_info:
            software_versions.append(server_info)
        
        if x_powered_by:
            software_versions.append(x_powered_by)
        
        # Print server info and check for vulnerabilities
        for software in software_versions:
            print(f"Checking software version: {software}")
            for software_name, vulnerable_versions in VULNERABLE_SOFTWARE_VERSIONS.items():
                if software_name.lower() in software.lower():
                    for version in vulnerable_versions:
                        if version in software:
                            print(f"[!] Vulnerable version found: {software_name} {version}")
                            return f"[!] Vulnerability detected in {software_name} {version}"
        
        return "[+] No outdated software detected"
    
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        return "[!] Error making request"

if __name__ == "__main__":
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    result = check_software_version(url)
    print(result)

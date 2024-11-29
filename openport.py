import nmap

def scan_ports(target):
    try:
        # Initialize the scanner
        nm = nmap.PortScanner()

        # Scan ports in the range 1-65535
        print(f"Scanning all ports on {target}...")
        nm.scan(hosts=target, arguments='-p 1-65535 -T4')

        # Display scan details
        if target in nm.all_hosts():
            print(f"\nDetails for {target}:\n")
            for proto in nm[target].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[target][proto].keys()
                for port in sorted(ports):
                    state = nm[target][proto][port]['state']
                    service = nm[target][proto][port].get('name', 'unknown')
                    print(f"Port: {port}, State: {state}, Service: {service}")
        else:
            print("No details found. The target may be down or blocking scans.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    website = input("Enter the website (e.g., example.com): ").strip()
    scan_ports(website)

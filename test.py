
import os

def load_payloads(file_path):
    """
    Load payloads from a given file. Each payload should be on a new line.
    """
    try:
        print(f"Checking access to file: {file_path}")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File does not exist: {file_path}")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"No read access to the file: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)

# Example usage
payload_file = r"C:\Users\DEVANSH\Downloads\test2\PayloadsAllTheThings\XSS Injection\Intruders"
payloads = load_payloads(payload_file)

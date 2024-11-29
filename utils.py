import requests

def check_headers(url):
    """
    Function to fetch headers for a given URL.
    Returns a dictionary with the headers or an error message.
    """
    try:
        response = requests.head(url, allow_redirects=True)
        headers = dict(response.headers)  # Get headers as dictionary
        return {"success": True, "headers": headers}
    except Exception as e:
        return {"success": False, "error": str(e)}

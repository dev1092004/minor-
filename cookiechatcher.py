
from datetime import datetime
import requests

def capture_cookie_from_url(target_url):
    """
    Captures cookies from the provided URL and returns them as a list of dictionaries.
    """
    try:
        # Send a request to the target URL
        response = requests.get(target_url)
        cookies = response.cookies
        time_str = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

        cookie_data = []

        if cookies:
            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'date': time_str,
                    'target_url': target_url
                }
                cookie_data.append(cookie_info)

                # Optionally save to file
                with open('cookies.txt', 'a') as cookie_file:
                    cookie_file.write(f'[+] Date: {time_str}\n')
                    cookie_file.write(f'[+] Target URL: {target_url}\n')
                    cookie_file.write(f'[+] Cookie Name: {cookie.name}\n')
                    cookie_file.write(f'[+] Cookie Value: {cookie.value}\n')
                    cookie_file.write(f'---\n')

        return cookie_data if cookie_data else None

    except Exception as e:
        return f"An error occurred: {e}"

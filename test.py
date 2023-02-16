import requests

def is_tor_node(ip_address):
    url = f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip_address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and ip_address in response.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return False

# Example usage:
ip = "118.193.41.43"
if is_tor_node(ip):
    print(f"{ip} is a Tor node.")
else:
    print(f"{ip} is not a Tor node.")

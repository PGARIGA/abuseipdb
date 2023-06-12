import sys
import requests

def check_ip_reputation(api_key, ip_address):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    data = response.json()

    if response.status_code == 200:
        if data["data"]["abuseConfidenceScore"] > 0:
            print(f"IP Address: {ip_address}")
            print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
            print(f"Country: {data['data']['countryName']}")
            print(f"ISP: {data['data']['isp']}")
            print(f"Usage Type: {data['data']['usageType']}")
            print(f"Domain: {data['data']['domain']}")
            print(f"Total Reports: {data['data']['totalReports']}")
            print(f"Last Reported At: {data['data']['lastReportedAt']}")
        else:
            print(f"IP address {ip_address} has no reported abuses.")
    else:
        print(f"Error occurred while checking IP reputation for {ip_address}.")

# Read IP addresses from file
def read_ip_addresses(file_path):
    with open(file_path, "r") as file:
        ip_addresses = file.read().splitlines()
    return ip_addresses

# Check reputation for each IP address
def check_reputation_for_ip_addresses(api_key, ip_addresses):
    for ip in ip_addresses:
        check_ip_reputation(api_key, ip)
        print("------------------")

# Get input file path and API key from command-line arguments
if len(sys.argv) < 3:
    print("Please provide the input file path and API key as command-line arguments.")
    sys.exit(1)

input_file = sys.argv[1]
api_key = sys.argv[2]
ip_addresses = read_ip_addresses(input_file)
check_reputation_for_ip_addresses(api_key, ip_addresses)

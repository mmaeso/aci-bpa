import requests
import json
import argparse
import jmespath
import re
from getpass import getpass
from ipaddress import ip_address
from rich.console import Console
from rich.table import Table

# Parse arguments from the command line
class Parser():

    @staticmethod
    def get_args():
        parser = argparse.ArgumentParser(prog="aci-bpa", description="ACI Best Practices Analyzer")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-a", "--apic", type=valid_hostname, help="Hostname of the APIC controller",dest="apic_ip")
        group.add_argument("-i", "--apic_ip", type=valid_ip_address, help="IP address of the APIC controller",dest="apic_ip")
        parser.add_argument("-u", "--user", type=str, help="Username to login into the APIC controller",dest="username", required=True)
        parser.add_argument("-p", "--password", type=str, 
                            help="(Optional) Password to login into the APIC controller.If not present, the program will ask you to input the password.It is not recommended to use this argument", 
                            dest="password"
                            )
        return parser.parse_args()

# Custom Argparse validator for IPv4/IPv6 Addresses
def valid_ip_address(ip):
    try:
        return ip_address(ip)
    except ValueError:
        msg = "Invalid IP address. Expected an IPv4 or IPv6 address"
        raise argparse.ArgumentTypeError(msg)

# Custom Argparse validator for hostnames
def valid_hostname(hostname):
    searchstring = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"
    match = re.fullmatch(searchstring,hostname)
    if match != None:
        return hostname
    else:
        msg = "Invalid Hostname. Accepted characters are: letters, numbers and hyphens"
        raise argparse.ArgumentTypeError(msg)
    
# Load features into a dictionary
def load_feature_list(file = "features.json"):
    with open(file, mode="r") as file:
        return json.load(file)

# Setup API parameters
def setup_api():
    args = Parser.get_args()
    aci_url = f"https://{args.apic_ip}/api"
    username = args.username
    if args.password:
        password = args.password
    else:
        password = getpass(prompt="Enter the APIC password for the provided username ({}): ".format(args.username))
    try:
        token = get_token(aci_url,username,password)
    except KeyError:
        raise KeyError("Invalid Password") from None
    return aci_url,token

# Get Login Token
def get_token(aci_url,username,password):  
    url = f"{aci_url}/aaaLogin.json"
    payload = {
        "aaaUser": {
        "attributes": {
            "name": f"{username}",
            "pwd": f"{password}"
            }
        }
    }
    headers = {
        "Content-Type" : "application/json"
    }
    requests.packages.urllib3.disable_warnings()
    try:
        response = requests.post(url,data=json.dumps(payload), headers=headers, verify=False).json()
        token = response["imdata"][0]["aaaLogin"]["attributes"]["token"]
    except requests.exceptions.ConnectionError as err:
        raise ConnectionError(err) from None
    return token

# Send API GET request
def send_get_request(url):
    headers = {
    "Cookie" : f"APIC-Cookie={token}", 
    }
    requests.packages.urllib3.disable_warnings()
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
        return None

# Check feature status
def check_feature_status(aci_url):
    features = load_feature_list()
    for feature in features:
        feature_url = f"{aci_url}{feature['url']}"
        response = send_get_request(feature_url)
        if response:
            feature["status"] = jmespath.search(feature["querystring"], response)
            if feature["status"] == "":
                feature["status"] = "disabled"
    
    return features

# Format feature data into a table
def format_data(*data):
    table = Table(show_header=True)
    table.add_column("Feature")
    table.add_column("Status", justify="right")

    for feature in data:
        if feature["status"] == feature["desired_status"]:
            table.add_row(feature["name"],f"[green]{feature['status']}[/green]")
        else:
            table.add_row(feature["name"],f"[red]{feature['status']}[/red]")
    return table

def main():
    global token
    aci_url, token = setup_api()
    features = check_feature_status(aci_url)
    table = format_data(*features)
    console = Console()
    console.print(table)

    for feature in features:
        if feature["status"] != feature ["desired_status"]:
            print(f"\n{feature['description']}")

    print("\nReferences\n--------")
    print("[1]Unofficial ACI Guide: https://unofficialaciguide.com/2021/07/16/aci-best-practice-configurations/")
    print("[2]ACI Fabric Endpoint Learning White Paper: https://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/application-centric-infrastructure/white-paper-c11-739989.html")
    print("[3]Cisco ACI Best Practices Summary: https://www.cisco.com/c/en/us/td/docs/dcn/whitepapers/cisco-aci-best-practices-quick-summary.html")

if __name__ == "__main__":
    main()
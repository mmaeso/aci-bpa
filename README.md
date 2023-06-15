## ACI Best Practices Analyzer
Simple script to check the global settings described in https://unofficialaciguide.com/2021/07/16/aci-best-practice-configurations/. 

## Environment
The script has been tested against ACI Simulator versions 4.2 and 5.1, and 6.0 on the Devnet Always On sandbox.
## Usage
Clone the project to your system and run the following:
`python3 -m pip install -r requirements.txt`

After cloning and installing the requirementes, imply run the script using:
`python3 aci-bpa.py -i <apic ip address> -u <username> `
or:
`python3 aci-bpa.py -a <apic hostname> -u <username>`

You can optionally pass the password as a command line argument using `-p <password>`. ** Important ** If your password has special characters you should encase it in single quotes.

## Output

The script checks a number of global settings and prints a table with the current status of the features, and recommendations based on the ACI Best Practice documentation. After running the script, you should see an output similar to:

| Feature            | Status   |
|--------------------|----------|
| mcp                | <span style="color:green">enabled</span>  |
| mcp_pdu_per_vlan   | <span style="color:red">disabled</span> |
| remote_ep_learn    | <span style="color:green">enabled</span>  |
| ep_loop_detection  | <span style="color:green">disabled</span> |
| ip_aging           | <span style="color:green">enabled</span>  |
| rogue_ep_detection | <span style="color:red">disabled</span> |
| strict_coop_gp     | <span style="color:green">strict</span>   |

MCP PDU per VLAN should be enabled. This feature enables MCP to send packets on a per-EPG basis, otherwise, these packets will only be sent on untagged EPGs.\nMCP PDU per VLAN can be enabled by going to Fabric -> Access Policies -> Policies -> Global -> MCP Instance Policy Default, and checking the 'Enable MCP PDU per VLAN' box.

References
--------
[1]Unofficial ACI Guide: https://unofficialaciguide.com/2021/07/16/aci-best-practice-configurations/
[2]ACI Fabric Endpoint Learning White Paper: https://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/application-centric-infrastructure/white-paper-c11-739989.html
[3]Cisco ACI Best Practices Summary: https://www.cisco.com/c/en/us/td/docs/dcn/whitepapers/cisco-aci-best-practices-quick-summary.html
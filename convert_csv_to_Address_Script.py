import csv
import re
from collections import defaultdict
import sys

def extract_prefix(hostname):
    # Extract prefix by removing trailing numbers (if any)
    return re.match(r'^(.*?)(?:\d+)$', hostname).group(1) if re.match(r'^(.*?)(?:\d+)$', hostname) else hostname

def convert_csv_to_firewall_config(csv_file, txt_file):
    # Initialize configuration lines for addresses
    config_lines = ['config firewall address']
    groups = defaultdict(list)  # Create dictionary to group hostnames by prefix
    addresses = []

    # Mapping of subnet mask to CIDR
    subnet_to_cidr = {
        "255.255.255.255": "/32",
        "255.255.255.254": "/31",
        "255.255.255.252": "/30",
        "255.255.255.248": "/29",
        "255.255.255.240": "/28",
        "255.255.255.224": "/27",
        "255.255.255.192": "/26",
        "255.255.255.128": "/25",
        "255.255.255.0": "/24",
        "255.255.254.0": "/23",
        "255.255.252.0": "/22",
        "255.255.248.0": "/21",
        "255.255.240.0": "/20",
        "255.255.224.0": "/19",
        "255.255.192.0": "/18",
        "255.255.128.0": "/17",
        "255.255.0.0": "/16",
        "255.254.0.0": "/15",
        "255.252.0.0": "/14",
        "255.248.0.0": "/13",
        "255.240.0.0": "/12",
        "255.224.0.0": "/11",
        "255.192.0.0": "/10",
        "255.128.0.0": "/9",
        "255.0.0.0": "/8",
        "254.0.0.0": "/7",
        "252.0.0.0": "/6",
        "248.0.0.0": "/5",
        "240.0.0.0": "/4",
        "224.0.0.0": "/3",
        "192.0.0.0": "/2",
        "128.0.0.0": "/1",
        "0.0.0.0": "/0"
    }

    # Read CSV and collect information
    with open(csv_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            name = row['hostname']
            ip = row['ip address']
            subnet = row['Subnetmask']
            comment = row['comment'].strip() if row['comment'] else None
            cidr = subnet_to_cidr.get(subnet, "/32")  # Default to /32 if subnet not in mapping
            address_name = f"{name}_{ip}{cidr}"
            addresses.append(address_name)

            # Extract prefix and add to group
            prefix = extract_prefix(name)
            groups[prefix].append(address_name)

            # Add address configuration
            config_lines.append(f'edit "{address_name}"')
            config_lines.append(f'        set subnet {ip} {subnet}')
            if comment:  # Only add set comment if comment is not empty
                config_lines.append(f'        set comment "{comment}"')
            config_lines.append('next')

    # Close address configuration
    config_lines.append('end')
    yield '\n'.join(config_lines) + '\n'

    # Create groups based on prefixes
    config_lines = ['config firewall addrgrp']
    for prefix, members in groups.items():
        if len(members) > 1:  # Create group only if there are more than 1 member
            config_lines.append(f'edit "{prefix}"')
            member_str = ' '.join(f'"{member}"' for member in members)
            config_lines.append(f'        set member {member_str}')
            config_lines.append('next')
    config_lines.append('end')
    yield '\n'.join(config_lines) + '\n'

def create_csv_template():
    # Create a sample CSV template file
    template_file = 'template.csv'
    with open(template_file, 'w') as f:
        f.write('hostname,ip address,Subnetmask,comment\n')
        f.write('example-host01,192.168.1.1,255.255.255.255,host\n')
        f.write('example-host02,192.168.1.2,255.255.255.255,host\n')
        f.write('example-network,192.168.0.0,255.255.0.0,network\n')
    print(f"CSV template created: {template_file}")

# Check if CSV file name is provided as argument
if len(sys.argv) != 2:
    print("Usage: python3 script.py <csv_file>")
    print("\nThis script converts a CSV file to a firewall configuration file.")
    print("\nExpected CSV format:")
    print("The CSV file must have the following columns:")
    print("  - hostname: Name of the host (e.g., mc-core-api01)")
    print("  - ip address: IP address of the host (e.g., 172.80.11.32)")
    print("  - Subnetmask: Subnet mask (e.g., 255.255.255.255 for /32, 255.255.0.0 for /16)")
    print("  - comment: Optional comment (e.g., host, network; leave blank if not needed)")
    print("\nExample CSV content:")
    print("hostname,ip address,Subnetmask,comment")
    print("mc-core-api01,172.80.11.32,255.255.255.255,host")
    print("mc-core-api02,172.80.11.33,255.255.255.255,host")
    print("AWS-ZONE,172.70.0.0,255.255.0.0,network")
    print("\nTo create a template CSV file, type 'y' and press Enter (or press Enter to exit):")
    response = input().strip().lower()
    if response == 'y':
        create_csv_template()
    sys.exit(1)

# Get input CSV file from command line argument
csv_file = sys.argv[1]

# Generate output TXT file name (replace .csv with .txt)
txt_file = csv_file.replace('.csv', '.txt')

# Write to the output file
with open(txt_file, 'w') as txtfile:
    for line in convert_csv_to_firewall_config(csv_file, txt_file):
        txtfile.write(line)

print(f"Output written to {txt_file}")

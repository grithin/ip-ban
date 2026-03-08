import csv
import ipaddress
def find_delimiter(filename):
    with open(filename, 'r') as fp:
        sniffer = csv.Sniffer()
        # Read a sample to allow the sniffer to analyze
        sample = fp.read(5000)
        delimiter = sniffer.sniff(sample).delimiter
        return delimiter



def get_starting_ip_from_cidr(cidr_block):
    """
    Retrieves the starting IP address (network address) from a CIDR block.

    Args:
        cidr_block (str): The CIDR block in string format (e.g., "192.168.1.0/24").

    Returns:
        ipaddress.IPv4Address: The starting IP address of the CIDR block.
    """
    try:
        network = ipaddress.ip_network(cidr_block, strict=False)
        return ipaddress.ip_address(str(network.network_address))
    except ValueError as e:
        raise(e)
"""
# Example usage:
cidr_block_ipv4 = "192.168.1.0/24"
starting_ip_ipv4 = get_starting_ip_from_cidr(cidr_block_ipv4)
print(f"The starting IP of {cidr_block_ipv4} is: {starting_ip_ipv4}")

cidr_block_ipv6 = "2001:0db8::/32"
starting_ip_ipv6 = get_starting_ip_from_cidr(cidr_block_ipv6)
print(f"The starting IP of {cidr_block_ipv6} is: {starting_ip_ipv6}")
"""

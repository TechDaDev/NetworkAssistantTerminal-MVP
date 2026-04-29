from app.services.topology_parsers import parse_cisco_cdp_neighbors, parse_cisco_lldp_neighbors, parse_mikrotik_arp


def test_cdp_parser_handles_detail_output():
    output = """
Device ID: Switch-B
Entry address(es):
  IP address: 192.168.88.20
Platform: cisco WS-C2960,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/24
"""
    records = parse_cisco_cdp_neighbors(output)

    assert records[0].name == "Switch-B"
    assert records[0].management_ip == "192.168.88.20"
    assert records[0].local_interface == "GigabitEthernet0/1"


def test_lldp_parser_handles_detail_output():
    output = """
Local Intf: Gi0/1
Chassis id: 0011.2233.4455
Port id: Gi0/24
System Name: access-switch
System Description: Cisco IOS Software
Management Address: 192.168.88.21
"""
    records = parse_cisco_lldp_neighbors(output)

    assert records[0].name == "access-switch"
    assert records[0].management_ip == "192.168.88.21"
    assert records[0].neighbor_interface == "Gi0/24"


def test_mikrotik_arp_parser_handles_print_output():
    output = """
 # ADDRESS         MAC-ADDRESS       INTERFACE
 0 192.168.88.20   AA:BB:CC:DD:EE:FF bridge
"""
    records = parse_mikrotik_arp(output)

    assert records[0].ip_address == "192.168.88.20"
    assert records[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert records[0].interface == "bridge"

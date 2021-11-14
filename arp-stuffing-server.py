#!/usr/bin/env python3

import argparse
import os
from scapy.all import Ether,IP,IPSession,ICMP,get_working_ifaces,hexdump,raw,sniff
import signal
import sys

def signal_handler(signal_number, frame):
    print('Signal %s is captured, exiting ...' %(signal_number))
    sys.exit(0)

def get_payload(packet, packet_payload):
    packet_payload.clear()

    # Ethernet fields
    packet_payload['ether_src'] = packet[Ether].getfieldval('src')
    packet_payload['ether_dst'] = packet[Ether].getfieldval('dst')

    # IP fields
    packet_payload['ip_src'] = packet[IP].getfieldval('src')
    packet_payload['ip_dst'] = packet[IP].getfieldval('dst')

    return packet_payload

def sniff_stop_callback(packet):
    icmp_type = packet[IP].getfieldval('type')
    icmp_code = packet[IP].getfieldval('code')

    # return True if ICMP Echo Request packet is captured
    if icmp_type == 8 and icmp_code == 0:
        return True

def setup_network(packet_payload):
    ethernet_interface = packet_payload['ethernet_interface_name']
    ip_address = packet_payload['ip_dst']
    netmask = packet_payload['netmask']

    # set up ethernet interface IP address
    set_up_interface_rc = os.system('ip addr add %s/%d dev %s' %(ip_address, netmask, ethernet_interface))

    if set_up_interface_rc != 0:
        return False
    else:
        print('The interface %s is set up with IP address %s.' %(ethernet_interface, ip_address))

    # bring up interface
    bring_up_interface_rc = os.system('ip link set dev %s up' %(ethernet_interface))

    if bring_up_interface_rc != 0:
        return False
    else:
        print('The interface %s is up.' %(ethernet_interface))

    return True

def get_interfaces_info():
    interfaces_dict = {}

    for interface in get_working_ifaces():
        if_name = interface.name
        if_mac = interface.mac

        interfaces_dict[if_name] = if_mac

    return interfaces_dict

def display_interfaces_info(interfaces_dict):
    interfaces_string = ' '.join([k+'|'+v for k,v in interfaces_dict.items()])

    return interfaces_string

if __name__ == '__main__':
    # pre-set required variables
    interfaces = get_interfaces_info()
    arp_stuffing_config = {}

    # register the signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # set up command arguments
    parser = argparse.ArgumentParser(description='ARP Stuffing Server - Scapy Version')
    parser.add_argument('--interface', type=str, required=True, help='Interface to be configured (interfaces: %s)' %(display_interfaces_info(interfaces)))
    parser.add_argument('--netmask', type=int, required=True, help='Netmask Prefix value for the configured IP address')
    args = parser.parse_args()

    # scapy needs superuser permission to send packets. check EUID and exit if it's not root user
    euid = os.geteuid()
    if euid != 0:
        print('Please run this utility under root user permission.')
        sys.exit(2)

    # check if the passed interface name exists in the running system
    if args.interface not in interfaces:
        print('%s is not a valid interface name.' %(args.interface))
        sys.exit(3)

    # start sniffing(ICMP Type 8) and stop if an ICMP Echo Rquest packet is received
    # sniff() call can only sniff on conf.iface interface by default, we must pass iface parameter to make it work
    sniff(iface=args.interface, filter='icmp and ip[20] == 8', session=IPSession, lfilter=lambda p: get_payload(p, arp_stuffing_config), stop_filter=lambda p: sniff_stop_callback(p))

    # print the ICMP Echo Request fields from the arp_stuffing_config
    print('##### ICMP Echo Request Packet Data Payload Fields #####')
    for k,v in arp_stuffing_config.items():
        print(k+': '+str(v))
    print()

    # save arguments into arp_stuffing_config for further use
    arp_stuffing_config['ethernet_interface_name'] = args.interface
    arp_stuffing_config['netmask'] = args.netmask

    # print ethernet interface information
    print('##### Ethernet Interface Information #####')
    print('Ethernet Interface Name: %s' %(args.interface))
    print('Ethernet Interface MAC Address: %s' %(arp_stuffing_config['ether_dst']))
    print()

    # set up network configurations
    setup_network_flag = setup_network(arp_stuffing_config)

    if setup_network_flag:
        print('Network configuration setup done.')
    else:
        print('Failed to set up network configuration.')
        sys.exit(3)

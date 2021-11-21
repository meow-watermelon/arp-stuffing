# ARP Stuffing

## Intro

ARP Stuffing itself is a popular way to set up an initial IP address on embedded devices that don't have a keyboard or similar input peripheral. Here are the basic steps to use ARP Stuffing:

1. The user's computer has an IP address stuffed manually into its address table (normally with the arp command with the MAC address taken from a label on the device)
2. The computer sends special packets to the device, typically a ping packet with a non-default size.
3. The device then adopts this IP address
4. The user then communicates with it by telnet or web protocols to complete the configuration.

I implemented the ARP Stuffing method in Python 3 by the [Scapy](https://scapy.readthedocs.io/en/latest/) module.

## Usage

The ARP Stuffing Server must run under effective UID **0**.

### Python Module Dependencies

```
argparse
os
scapy
signal
sys
```

### Command Dependencies

This utility uses [ip](https://man7.org/linux/man-pages/man8/ip.8.html) command to set up networking configurations.

### ARP Stuffing Server Usage

```
$ sudo ./arp-stuffing-server.py -h
usage: arp-stuffing-server.py [-h] --interface INTERFACE --netmask NETMASK

ARP Stuffing Server - Scapy Version

optional arguments:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Interface to be configured (interfaces: lo|00:00:00:00:00:00 enp1s0|52:54:00:1a:87:5d)
  --netmask NETMASK     Netmask Prefix value for the configured IP address
```

## Usage Examples

In this section, I use 2 Linux hosts to simulate Send Host and Target Host. Both are running Fedora 34. Users would notice I split some outputs to give better ideas on what actually happened. The example case I run is a successful running case.

Sender Host Ethernet Interface Name: `virbr0`

Sender Host Ethernet MAC Address: `52:54:00:df:56:26`   

Sender Host IP Address: `192.168.122.1`

Target Host Ethernet Interface Name: `enp1s0`

Target Host Ethernet MAC Address: `52:54:00:1a:87:5d`

Target Host IP Address: `192.168.122.105` (to be configured)

Target Host IP Address Netmask Prefix: `24` (to be configured)

1. Clear Target Host networking configurations - Target Host

```
# nmcli connection delete enp1s0
```

2. Add Target Host Interface's MAC Address into Send Host ARP table - Sender Host

```
$ sudo arp -s 192.168.122.105 '52:54:00:1a:87:5d'
```

3. Start ARP Stuffing Server - Target Host

```
# ./arp-stuffing-server.py --interface enp1s0 --netmask 24
```

4. Send ICMP Echo Request by ping command - Sender Host

```
$ ping -c 5 192.168.122.105
```

5. ARP Stuffing Server receives the ICMP Echo Request packet and set up networking configurations - Target Host

```
##### ICMP Echo Request Packet Data Payload Fields #####
ether_src: 52:54:00:df:56:26
ether_dst: 52:54:00:1a:87:5d
ip_src: 192.168.122.1
ip_dst: 192.168.122.105

##### Ethernet Interface Information #####
Ethernet Interface Name: enp1s0
Ethernet Interface MAC Address: 52:54:00:1a:87:5d

The interface enp1s0 is set up with IP address 192.168.122.105.
The interface enp1s0 is up.
Network configuration setup done.
```

6. Once Target Host IP is set up done, ping command starts to receive the ICMP Echo Reply packets from Target Host - Sender Host

```
[... continues from ping command output ...]
PING 192.168.122.105 (192.168.122.105) 56(84) bytes of data.
64 bytes from 192.168.122.105: icmp_seq=2 ttl=64 time=0.527 ms
64 bytes from 192.168.122.105: icmp_seq=3 ttl=64 time=0.763 ms
64 bytes from 192.168.122.105: icmp_seq=4 ttl=64 time=0.503 ms
64 bytes from 192.168.122.105: icmp_seq=5 ttl=64 time=0.688 ms

--- 192.168.122.105 ping statistics ---
5 packets transmitted, 4 received, 20% packet loss, time 4095ms
rtt min/avg/max/mdev = 0.503/0.620/0.763/0.108 ms
```

The first ICMP Echo Request packet is *lost* because this packet is used by ARP Stuffing Server to configure networking configurations and ARP Stuffing Server **DOES NOT** reply to the ICMP Echo Request packet. I want to leave all ICMP Request Reply packets handling to OS.

7. Target Host networking configurations are set up done - Target Host

```
# ip link show dev enp1s0
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:1a:87:5d brd ff:ff:ff:ff:ff:ff

# ip address show dev enp1s0
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:1a:87:5d brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.105/24 scope global enp1s0
       valid_lft forever preferred_lft forever
```

Now, user can connect to Target Host to set up other network parameters like gateway and DNS.

## Notes and Thoughts

1. The IP address netmask would be `255.255.255.255` if we don't specify the netmask prefix in `ip` command.

2. **DO NOT** run ARP Stuffing Server on a host that has networking configuration set up properly already. This may cause unpredictable results. Remember, ARP Stuffing should be only used for devices that don't have networking configurations.

Any thoughts and suggestions are welcome, Thanks!

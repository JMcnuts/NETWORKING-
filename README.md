# NETWORKING

## PROTOCOL DATA UNIT (PDU):
```
Session-Application = Data
Transport = Segment/Datagram
Network = Packet
Data Link = Frame
Physical = Bit
```
## INTERNET STANDARD ORGANIZATIONS 
```
IETF's-RFC's . (Internet Engineering Task Force). The ones responsible for writing and developing RFCs (guidelines)
IANA (Internet Assigned Numbers Authority)- Internet Numbers. IPV4,IPV6 address allocations, WK ports management, MAC OUI assigned to organizations (first 6 organizational identifiers, last 6 personal identifier)
IEEE (Institute of Electrical and Electronics Engineers). International, main standards are IEEE 802.11 (Wireless LAN), IEEE 802.3 (Ethernet), 802.10 (VLAN), IEEE 802.16 (Broadband Wireless Access, BWA), IEEE 802.1x (Port-based network access control standards,
used for authenticating and authirizing devices connecting to a LAN or WLAN, IEEE 802.1ad (Provider Bridging, PB, Standards) also known as Q-in-Q for implementing virtual LAN (VLAN) stacking in Ethernet networks).
```
## OSI layer and units -R
```
-Binary. Bit, Nibble (4 bits), Byte (8 bits), Half Word (16 bits), Word (32 bits)
-Decimal 
-Hex (0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F)
```
```
0XB7
8 4 2 1 8 4 2 1
1 0 1 1 0 1 1 1
0XB7 to Dec = B=11, (11x16)+(7x16) = 183
```
## Network topologies: Bus, RIng, Mesh, Wireless, Hierarchical.
## Network devices: Hub, Repeater, Switch, Router. 

## Speed	Bit-time
```
10 Mbps  100ns

100 Mbps  10ns

1 Gbps     1ns

10 Gbps   .1ns

100 Gbps .01ns
```
```
MAC. Medium Access Control. Controls transpond from layer 2 to layer 3.
LLC. Logical Link Control. Controls transpond from layer 3 to layer 2.
CAM table (Content-addressable memory) allows very fast searching and table lookups. 
```

## Switching Modes:
```
-Store-and-Forward accepts and analyzes the entire frame before forwarding it to its destination. It takes more time to examine the entire frame, but it allows the switch to catch certain frame errors and collisions and keep them from propagating bad frames through the network. This method is required to switch frames between links of different speeds; this is due to bit-timing. The speed at which the bits enter one interface may be slower than the speed at which the switch needs to send the bits to a different interface.

-Cut-Through (sometimes called fast forward) only examines the destination address before forwarding it to its destination segment. This is the fastest switching mode but requires the interfaces to be the same speed.

-Fragment-Free read at least 64 bytes of the Ethernet frame before switching it to avoid forwarding Ethernet runt frames (Ethernet frames smaller than 64 bytes). A frame should have a minimum of 46 bytes of payload plus its 18-byte frame header.
```
# CAM Table Overflow/Media Access Control (MAC) Attack - RESEARCH

```
MAC addresses 48-bit/6-Byte/12-Hex
```

## MAC Spoofing
```
Spoofing is the act of disguising a communication from an unknown source as being from a known or trusted source. Spoofing is an attack vector done at several different layers of the OSI. At the Data-link layer attackers will commonly spoof the MAC-address.

Originally MAC addresses were hard coded into the firmware of the NIC and could not be easily changed. This is why MAC addresses were commonly called "Firmware", "Hardware", or "Burned-in" addresses. In order to facilitate MAC spoofing attacks it required crafting of special frames with the MAC address pre-programmed in.

Today most MAC addresses are programmed using the software. This makes modification of a device’s MAC address much simpler. In order to perform a MAC spoofing attack the malicious actor can either change their MAC address to a known or trusted address or create crafted frames with the MAC address already programmed in. MAC spoofing can be used to perform:

ARP-Cache poisoning - modify the ARP cache of devices on the same network segment.

ARP Man-in-the-middle (MitM) attacks - Specially crafted ARP messages to force 2 or more victims to send traffic thru the attacker’s system. Here the attacker can sniff or alter traffic.
```
VLAN. Logically separates a network within the same hardware.


```
VLAN hopping Attack

VLAN hopping is an exploit method of attacking networked devices on separate virtual LAN (VLAN) without traversing a router or other Layer 3 device. The concept behind VLAN hopping attacks is for the attacker on one VLAN to gain access to traffic on other VLANs that would normally not be accessible. Keep in mind that VLAN hopping is typically a one-way attack. It will not be possible to get any response from the target device unless methods are setup on the target to respond with similar vlan hopping methods.

There are three primary methods of VLAN hopping:

Switch Spoofing

In this attack, an attacking host imitates a trunking switch by crafting Dynamic Trunking Protocol (DTP) frames in order to form a trunk link with the switch. With a trunk link formed the attacker can then use tagging and trunking protocols such as ISL or 802.1q. Traffic for all VLANs is then accessible to the attacking host.

switch(config)# interface fastethernet 1/10
switch(config-if)# switchport mode access
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport access vlan 10
switch(config)# iterface gigabit 0/1
switch(config-if)# switchport trunk encapsulation dot1q
switch(config-if)# switchport mode trunk
switch(config-if)# switchport nonegotiate
Tagging

This attack typically requires the attacker add the target 802.1Q tag manually to an Ethernet frame even though it is an access port. This process is normally done by the switch. The switch will receive the frame and forward it out the trunk port leading to the target without it needing to be routed. This method requires that the attacker and victim are separated by a trunk and success depends on the switch firmware being vulnerable.

Double Tagging

This attack works if the attacker knows what the "native VLAN" that is used on your organization. Typically VLAN 1 is used. All VLANs will be "tagged" with its corresponding VLAN. The Native VLAN however is intended for local network communication and is not tagged. Thus anything tagged for the native VLAN will be stripped off. The attacker will insert 2 tags into their frames. The first tag will be for the Native VLAN and the second tag will be for whatever VLAN he is trying to access. Upon receipt the switch will then remove the Native VLAN tag and will leave the second VLAN tag in tact. This method also requires that the attacker and victim be separated by a trunk and a vulnerable switch.

switch(config)# vlan dot1q tag native
switch(config)# interface fastethernet 1/10
switch(config-if)# switchport mode access
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport access vlan 10
switch(config)# iterface gigabit 0/1
switch(config-if)# switchport trunk encapsulation dot1q
switch(config-if)# switchport mode trunk
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport trunk native vlan 999


```
## VTP Trunking Protocol:

```
VLAN Trunking Protocol (VTP) is a Cisco proprietary protocol that propagates the definition of Virtual Local Area Networks (VLAN) on the whole local area network. VLAN Trunk Protocol (VTP) was developed to help reduce the administration of creating VLANs on all switches within a switched network. To do this, VTP sends VLAN information to all the switches in a VTP domain.

Server - can create, modify or delete VLANs. Can create and forward VTP messages.

Client - can only adopt VLAN information in VTP messages. Can forward VTP messages.

Transparent - only forwards VTP messages but does not adopt any of the information.

VTP advertisements are sent over all trunk links. VTP messages advertise the following on its trunk ports:

Management domain

Configuration revision number

Known VLANs and their specific parameters

There are three versions of VTP, version 1, version 2, version 3.

VTP is Cisco propietary 
```

## Dynamic Trunking Protocol (DTP):
```
The Dynamic Trunking Protocol (DTP) is a Cisco proprietary Layer 2 protocol. Its purpose is to dynamically negotiate trunking on a link between two switches running VLANS. It can also negotiate the type of trunking protocol to be used on the link (802.1q or ISL). DTP works by exchanging small DTP frames between two supporting devices to negotiate the link parameters.

Most switches will have DTP enabled by default in either "Dynamic-Auto" or "Dynamic-Desirable" modes.

```
## DTP Attack (Switch Spoofing):

```
DTP Attack (Switch Spoofing)
DTP attacks relate to the VLAN hopping attack discussed earlier. Attackers can craft their own DTP frames in order to negotiate a trunk link between their device and the switchport. This trunking connection would allow the attacker to communicate with all VLANs on the switch and to inject traffic into whatever VLAN they desire. Typically the trunk link will not be "pruned" or allowed VLANs specified so this connection will allow the attacker access to all VLANs on that switch. This attack is sometimes called "Switch Spoofing".

This attack can be mitigated by using the switchport nonegotiate interface command to disable DTP. Additionally you should manually assign switchports to either Access (switchport mode access) or Trunk (switchport mode trunk).

```
```
## Splunk, SO, Suricata, Elastic, Kibana, WS, CyberChef. -R 
```
Network traffic sniffers (Active-nmap, Passive)

# TCP Dump and filters 
```
sudo tcpdump -A #print payload in ASCII
sudo tcpdump -D #list all interfaces
sudo tcpdump -i #specify capture interface
sudo tcpdump -e #print data-link headers 
sudo tcpdump -X or XX #print payloac in HEX and ASCII
sudo tcpdump -r analysis-exam.pcap -XX -vv #Will give you everything, ensure you are in the right dir.
sudo tcpdump port 80 or 22 -vn
sudo tcpdump icmp
sudo tcpdump ip
```
## sockets and snippers -R
## byte offsets -R
```
https://www.wains.be/pub/networking/tcpdump_advanced_filters.txt
```
```
https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693
```
```
https://packetlife.net/media/library/12/tcpdump.pdf
```
Can you use tcpdump to nail down a search on a big PCAP and output the search to create a reduced PCAP to open later on WS.
```
0x81000 VLAN header -R
0x8dd double packing -R
```

## BITWISE MASKING EX.
```
tcpdump 'ether[12:4] & 0xffff0fff = 0x81000abc #look at ether byte 12 and look at 4 bytes and exact matcher/0 Not important (QoS) -PCP/DEIR
tcpdump 'ip[1] & 252 = 32' -Q re-explain look for a DSCP of 32 
```
## Filter Logic- Most exclusive:
```
tcp[13] = 0x11 #all bits must match ACK/FIN mask - or 1
```
```
tcp[13] & 0x11 = 0x11 #ACK/FIN both have to be on. 
```
```
tcp[13] & 0x11 > 0 Can be any combination except both off
tcp[13] & 0x11 !=0 Can be any combination except both off
```
BPFS -R


# BPF Filters CTF
 tcpdump 'ip6[6] = 17 || ip[9] = 17' -r BPFCheck.pcap | wc -l #Looks for all ipv4 and ipv6 headers that are UDP.
 tcpdump -n ' ip[8] < 65 ||  ip6[7] < 65' -r BPFCheck.pcap | wc -l #Looks for all ipv4 and ipv6 headers that have a ttl of 64 or less.
 tcpdump 'tcp[0:2] >1024 || udp[0:2] > 1024' -r BPFCheck.pcap | wc -l #Looks for all packets that are TCP and have a port > than 1024.

What is the Berkeley Packet Filter, using tcpdump, to capture all packets with an IP ID field of 213?
tcpdump 'ip[4:2] = 213' -r BPFCheck.pcap | wc -l

What is the Berkeley Packet Filter, using tcpdump, to capture an attacker using vlan hopping to move from vlan 1 to vlan 10?
tcpdump -n 'ether[12:4] & 0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff = 0x8100000A' -r BPFCheck.pcap | wc -l `













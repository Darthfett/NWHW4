# Networks HW 4 #
Parse tcpdump output for IP addresses, and send ARP requests for unrecognized local IPs (IPs matching 192.168.*.*)

## Requirements ##
 * super user privileges
 * linux
 * tcpdump
   - `sudo apt-get install tcpdump`
 * gcc
   - `sudo apt-get install gcc`

## Configuration ##
 * In main.c
   - SOURCE_ADDRESS needs to be the same as your IPv4 local IP address (see output from ifconfig)
   - INTERFACE
   - ONLY_ARP_REQ_LOCAL can be set to 0 to send ARP requests for ALL IP addresses, or 1 for only local IP addresses (i.e. in the range 192.168.*.*)

## Compilation ##
 * `gcc -Wall main.c`

## Running ##
 * `sudo su` (to log in to super user)
 * `tcpdump -nS | ./a.out` (while logged in as super user)

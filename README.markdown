# Networks HW 4 #
Parse tcpdump output for IP addresses, and send ARP requests for unrecognized local IPs (IPs matching 192.168.*.*)

## Requirements ##
 * linux
 * tcpdump
   - `sudo apt-get install tcpdump`
 * gcc
   - `sudo apt-get install gcc`

## Compilation ##
 * `gcc -Wall main.c` (Use -Wall to enable **all W**arnings)

## Running ##
 * `sudo tcpdump -nS | ./a.out`

Or, alternatively, to test with a sample dump:

 * `./a.out < sample.txt`


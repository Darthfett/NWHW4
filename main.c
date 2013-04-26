
// Send an IPv4 ARP packet via raw socket at the link layer (ethernet frame).
// Values set for ARP request.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()
#include <netdb.h> // struct addrinfo
#include <sys/types.h> // needed for socket()
#include <sys/socket.h> // needed for socket()
#include <netinet/in.h> // IPPROTO_RAW
#include <netinet/ip.h> // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h> // inet_pton() and inet_ntop()
#include <sys/ioctl.h> // macro ioctl is defined
#include <bits/ioctls.h> // defines values for argument "request" of ioctl.
#include <net/if.h> // struct ifreq
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h> // errno, perror()

#include <time.h>

#define SOURCE_ADDRESS "192.168.1.116" // This computer's IP Address
#define DEST_ADDRESS "192.168.1.1"
#define INTERFACE "eth0"

#define CHECK_MEM_ERR(ptr) if (ptr == NULL) {fprintf(stderr, "Fatal: Memory Allocation Error\n"); exit(-1);}

time_t timer;

char **ip_table = NULL;
int ip_table_size = 1;
int ip_table_count = 0;

// Globals to store the MAC address found in an ARP Reply message
char ARP_MAC_address[1024];
int ARP_is_reply = 0;

typedef enum {
    UNKNOWN,
    TCP,
    ARP,
    IP,
    IP6,
} packet_t;

int seen_ip(char *ip) {
    int i;
    for (i = 0; i < ip_table_count; i++) {
        if (strcmp(ip, ip_table[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int add_ip(char *ip) {
    if (seen_ip(ip)) return 0;

    if (ip_table_count >= ip_table_size) {
        ip_table_size = ip_table_count * 2;
        ip_table = (char**) realloc((void*) ip_table, sizeof(char*) * ip_table_size);
    }
    ip_table[ip_table_count] = ip;
    ip_table_count++;
    return 1;
}

void init_ip_table() {
    ip_table = (char**) malloc(sizeof(char*) * ip_table_size);
    CHECK_MEM_ERR(ip_table);
}

void arp_request(char *ip) {
    if (!add_ip(ip)) {
        free(ip);
        return;
    }
    printf("Saw IP address: %s\n", ip);

    // TODO: Send arp request packet

    // Update current time
    time(&timer);
    return;
}

char** parse_TCP(char *pkt, int *count) {
    // Don't know what these look like, just treat as error for now
    return NULL;
}

#define ARP_PKT_COUNT 2
char** parse_ARP(char *pkt, int *count) {
    // Parse an ARP packet for IPs
    int i;
    char **IPs = (char**) malloc(sizeof(char*) * ARP_PKT_COUNT);
    CHECK_MEM_ERR(IPs);

    if (strncmp(pkt, "Request", strlen("Request")) == 0) {
        // Allocate room for 2 IPs
        for (i = 0; i < ARP_PKT_COUNT; i++) {
            IPs[i] = (char*) malloc(sizeof(char) * 1024);
            CHECK_MEM_ERR(IPs[i]);
        }

        // Try and parse the IPs
        if (sscanf(pkt, "Request who-has %1023s tell %1023[^,]s, ", IPs[0], IPs[1]) != 2) {
            // Format did not match?
            fprintf(stderr, "Error parsing ARP Request packet: ");
            for (i = 0; i < ARP_PKT_COUNT; i++) {
                free(IPs[i]);
            }
            free(IPs);
            return NULL;
        }
        *count = 2;
        return IPs;
    } else if (strncmp(pkt, "Reply", strlen("Reply")) == 0) {
        // Allocate room for 1 IP
        IPs[0] = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(IPs);
        if (sscanf(pkt, "Reply %1023s is-at %1023[^,]s, ", IPs[0], ARP_MAC_address) != 2) {
            // Format did not match?
            fprintf(stderr, "Error parsing ARP Reply packet: ");
            free(IPs[0]);
            free(IPs);
            return NULL;
        }
        ARP_is_reply = 1;
        *count = 1;
        return IPs;
    }
    fprintf(stderr, "Error parsing ARP packet: ");
    free(IPs);
    return NULL;
}

#define IP_PKT_COUNT 2
char** parse_IP(char *pkt, int *count) {
    // Parse an IP packet for IPs
    int i;
    char **IPs = (char**) malloc(sizeof(char*) * IP_PKT_COUNT);
    CHECK_MEM_ERR(IPs);

    for (i = 0; i < IP_PKT_COUNT; i++) {
        IPs[i] = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(IPs[i]);
    }

    // Parse IP line for src and dest address (throw away rest)
    if (sscanf(pkt, "%1023s > %1023[^:]s ", IPs[0], IPs[1]) != 2) {
        fprintf(stderr, "Error parsing IP packet: ");
        for (i = 0; i < IP_PKT_COUNT; i++) {
            free(IPs[i]);
        }
        free(IPs);
        return NULL;
    }
    *count = IP_PKT_COUNT;
    return IPs;
}

char** parse_IP6(char *pkt, int *count) {
    // Parse an IP6 packet for IPs
    
    // Not currently supported
    *count = 0;
    return NULL;
}

void handle_line(char *ln) {
    /*
        Parse the given line for IP Addresses,
        then send ARP requests for any new/unrecognized IP Addresses
    */
    int i;
    char line[1024];
    strncpy(line, ln, 1024);
    
    packet_t type = UNKNOWN;
    char timestamp[1024];
    char pkt_type[1024];
    char rest[1024];
    
    // partially parse the packet for timestamp and type
    if (sscanf(line, "%1023s %1023s %1023[^\n]", timestamp, pkt_type, rest) != 3) {
        fprintf(stderr, "Unable to parse string:\n%s\n", ln);
        return;
    }
    
    // We don't care about the timestamp; get packet type
    if (strcmp(pkt_type, "TCP") == 0) {
        type = TCP;
    } else if (strcmp(pkt_type, "ARP,") == 0) {
        type = ARP;
    } else if (strcmp(pkt_type, "IP") == 0) {
        type = IP;
    } else if (strcmp(pkt_type, "IP6") == 0) {
        type = IP6;
    }

    // Parse the packet for IP Addresses
    char **IPs;
    int IP_count = -1;
    switch(type) {
    case TCP:
        IPs = parse_TCP(rest, &IP_count);
        break;
    case ARP:
        IPs = parse_ARP(rest, &IP_count);
        break;
    case IP:
        IPs = parse_IP(rest, &IP_count);
        break;
    case IP6:
        IPs = parse_IP6(rest, &IP_count);
        break;
    case UNKNOWN: // fall through
    default:
        fprintf(stderr, "Unknown packet type: %s\n\t%s\n", pkt_type, ln);
        return;
    }

    if (IP_count == -1) {
        fprintf(stderr, "%s\n", ln);
        return;
    }
    
    // filter nonlocal IP addresses and send ARP request for new addresses
    for (i = 0; i < IP_count; i++) {
        int a, b, c, d;

        // Parse first four numbers
        // This is because some packets are logged with port number,
        // e.g. 192.168.0.1.80
        if (sscanf(IPs[i], "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "Error parsing IP %s received from packet %s\n", IPs[i], ln);
            free(IPs);
            return;
        }

        // Check to see if this address is 192.168.*.*
        if (a != 192 || b != 168) continue;

        // Turn address back into string for sending an arp request
        char *ip = (char*) malloc(sizeof(char) * 1024);
        CHECK_MEM_ERR(ip);
        sprintf(ip, "%d.%d.%d.%d", a, b, c, d);

        // Send arp request (will automatically check if address is new)
        arp_request(ip);
    }
    // Free addresses that we are no longer using
    free(IPs);
}

int main(int argc, char **argv) {
    int i;
    char line[1024];

    init_ip_table();
    
    // Start timer
    time(&timer);
    while(1) {
        // Read line from stdin
        gets(line);

        // Quit when we reach end of file
        if (feof(stdin)) break;
        
        // Quit when 5 minutes have passed
        if (difftime(timer, time(NULL)) > 60 * 5) break;

        // Reset ARP reply flag
        ARP_is_reply = 0;
        
        // Parse and handle line
        handle_line(line);
    }
    
    // Free up memory (to make valgrind happy)
    for (i = 0; i < ip_table_count; i++) {
        free(ip_table[i]);
    }
    free(ip_table);
    return 0;
}
/*
// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    unsigned short htype;
    unsigned short ptype;
    unsigned char hlen;
    unsigned char plen;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};
// Define some constants.
#define IP4_HDRLEN 20 // IPv4 header length
#define ARP_HDRLEN 28 // ARP header length
#define ARPOP_REQUEST 1 // Taken from <linux/if_arp.h>

int main (int argc, char **argv)
{
    int i, status, frame_length, sd, bytes;
    char *interface, *target, *src_ip;
    arp_hdr arphdr;
    unsigned char *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;
    // Allocate memory for various arrays.
    tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
    if (tmp != NULL) {
        src_mac = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_mac'.\n");
        exit (EXIT_FAILURE);
    }
    memset (src_mac, 0, 6 * sizeof (unsigned char));
    tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
    if (tmp != NULL) {
        dst_mac = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_mac'.\n");
        exit (EXIT_FAILURE);
    }
    memset (dst_mac, 0, 6 * sizeof (unsigned char));
    tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
    if (tmp != NULL) {
        ether_frame = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'ether_frame'.\n");
        exit (EXIT_FAILURE);
    }
    memset (ether_frame, 0, IP_MAXPACKET * sizeof (unsigned char));
    tmp = (char *) malloc (40 * sizeof (char));
    if (tmp != NULL) {
        interface = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
        exit (EXIT_FAILURE);
    }
    memset (interface, 0, 40 * sizeof (char));
    tmp = (char *) malloc (40 * sizeof (char));
    if (tmp != NULL) {
        target = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
        exit (EXIT_FAILURE);
    }memset (target, 0, 40 * sizeof (char));
    tmp = (char *) malloc (16 * sizeof (char));
    if (tmp != NULL) {
        src_ip = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
        exit (EXIT_FAILURE);
    }
    memset (src_ip, 0, 16 * sizeof (char));
    // Interface to send packet through.
    strcpy (interface, INTERFACE);
    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }
    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close (sd);
    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);
    // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", interface);
    for (i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
    }
    printf ("%02x\n", src_mac[5]);
    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
    // Set destination MAC address: broadcast address
    memset (dst_mac, 0xff, 6);
    // Source IPv4 address: you need to fill this out
    strcpy (src_ip, SOURCE_ADDRESS);
    // Destination URL or IPv4 address (must be a link-local node): you need to fill this 
    out
    strcpy (target, DEST_ADDRESS);
    // Fill out hints for getaddrinfo().memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    // Resolve source using getaddrinfo().
    if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    memcpy (&arphdr.sender_ip, &ipv4->sin_addr, 4);
    freeaddrinfo (res);
    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4);
    freeaddrinfo (res);
    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6);
    device.sll_halen = htons (6);
    // ARP header
    // Hardware type (16 bits): 1 for ethernet
    arphdr.htype = htons (1);
    // Protocol type (16 bits): 2048 for IP
    arphdr.ptype = htons (ETH_P_IP);
    // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.hlen = 6;
    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.plen = 4;
    // OpCode: 1 for ARP request
    arphdr.opcode = htons (ARPOP_REQUEST);
    // Sender hardware address (48 bits): MAC address
    memcpy (&arphdr.sender_mac, src_mac, 6);
    // Sender protocol address (32 bits)
    // See getaddrinfo() resolution of src_ip.
    // Target hardware address (48 bits): zero, since we don't know it yet.
    memset (&arphdr.target_mac, 0, 6);
    // Target protocol address (32 bits)
    // See getaddrinfo() resolution of target.
    // Fill out ethernet frame header.// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data 
    (ARP header)
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6);
    memcpy (ether_frame + 6, src_mac, 6);
    // Next is ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    // Next is ethernet frame data (ARP header).
    // ARP header
    memcpy (ether_frame + 14, &arphdr, ARP_HDRLEN);
    // Submit request for a raw socket descriptor.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }
    // Send ethernet frame to socket.
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, 
        sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    // Close socket descriptor.
    close (sd);
    // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (ether_frame);
    free (interface);
    free (target);
    free (src_ip);
    return (EXIT_SUCCESS);
}
*/

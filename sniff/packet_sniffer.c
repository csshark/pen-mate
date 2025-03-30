#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>

pcap_t *handle;
pcap_dumper_t *dumpfile;
volatile sig_atomic_t capture_active = 1;  

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_dump(dumpfile, header, packet);

    printf("\n+-----------------------------------------------------+\n");
    printf("| Packet Length: %-7d \n", header->len);
    printf("+-----------------------------------------------------+\n");

    struct ip *iph = (struct ip*)(packet + 14);
    printf("| Source IP: %-15s                            \n", inet_ntoa(iph->ip_src));
    printf("| Destination IP: %-9s                            \n", inet_ntoa(iph->ip_dst));
    
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(packet + 14 + iph->ip_hl * 4);
        printf("| Protocol: TCP                                       \n");
        printf("| Source Port: %-10d                              \n", ntohs(tcph->source));
        printf("| Dest Port: %-12d                            \n", ntohs(tcph->dest));

        // Calculate where the TCP payload starts
        const u_char *tcp_payload = packet + 14 + iph->ip_hl * 4 + tcph->doff * 4;
        int payload_length = header->len - (14 + iph->ip_hl * 4 + tcph->doff * 4);

        // Only process if there's TCP payload
        if (payload_length > 0) {
            // Buffer to hold the TCP payload as a string for easier processing
            char *payload = (char *)malloc(payload_length + 1);
            memcpy(payload, tcp_payload, payload_length);
            payload[payload_length] = '\0'; // Null-terminate the string

            printf("| Payload Length: %-9d                        \n", payload_length);

            // Check if this is an HTTP request or response
            if (strncmp(payload, "GET", 3) == 0 || strncmp(payload, "POST", 4) == 0 ||
                strncmp(payload, "PUT", 4) == 0 || strncmp(payload, "DELETE", 6) == 0) {
                printf("| HTTP Request/Response Detected                    |\n");
                // Print HTTP headers until double CRLF
                char *header_end = strstr(payload, "\r\n\r\n");
                if (header_end != NULL) {
                    // Print each line of the header
                    char *header_start = payload;
                    printf("| HTTP Headers:\n");
                    while (header_start < header_end) {
                        // Find the end of this line
                        char *line_end = strstr(header_start, "\r\n");
                        if (line_end && line_end < header_end) {
                            *line_end = '\0'; // Temporarily null-terminate the line
                            printf("| %s\n", header_start);
                            header_start = line_end + 2; // Move to next line, skip CRLF
                        } else {
                            break; // We reached the end of the headers
                        }
                    }
                }
            }
            free(payload); // Clean up allocated memory
        }
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)(packet + 14 + iph->ip_hl * 4);
        printf("| Protocol: UDP                                      \n");
        printf("| Source Port: %-10d                               \n", ntohs(udph->source));
        printf("| Dest Port: %-12d                                 \n", ntohs(udph->dest));
    } else if (iph->ip_p == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr*)(packet + 14 + iph->ip_hl * 4);
        printf("| Protocol: ICMP                                     \n");
        printf("| Type: %-10d                                      \n", icmph->type);
        printf("| Code: %-10d                                      \n", icmph->code);
    } else {
        printf("| Protocol: Other (%-5d)                            \n", iph->ip_p);
    }
    printf("+-----------------------------------------------------+\n");
}

void stop_capture(int signum) {
    capture_active = 0;
    printf("\nStopping packet capture...\n");
    printf("\nOutput saved in 'capture.pcap' file! ");
    pcap_breakloop(handle);  
}

int main(int argc, char *argv[]) {
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <output.pcap>\n", argv[0]);
        return EXIT_FAILURE;
    }

    device = argv[1];
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return EXIT_FAILURE;
    }

    dumpfile = pcap_dump_open(handle, argv[2]);
    if (dumpfile == NULL) {
        fprintf(stderr, "Could not open dump file: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    signal(SIGINT, stop_capture); 

    printf("Listening on %s... Press Ctrl+C to stop capture.\n", device);

    pcap_loop(handle, -1, packet_handler, (u_char *)dumpfile);

    pcap_dump_close(dumpfile);
    pcap_close(handle);

    return EXIT_SUCCESS;
}

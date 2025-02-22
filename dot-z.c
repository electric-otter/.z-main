#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#define DNS_SERVER "1.1.1.1"  // Cloudflare DNS server
#define DNS_PORT 53
#define BUFFER_SIZE 512

// DNS header structure
struct DNSHeader {
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
};

// DNS question structure
struct DNSQuestion {
    unsigned short qtype;
    unsigned short qclass;
};

// DNS resource record structure (for A record)
struct DNSRecord {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned int addr;
};

// Function to build DNS query
void build_query(char *buffer, char *domain) {
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
    dns_header->id = htons(0x1234);  // Arbitrary transaction ID
    dns_header->flags = htons(0x0100);  // Standard query
    dns_header->questions = htons(1);
    dns_header->answers = 0;
    dns_header->authority = 0;
    dns_header->additional = 0;

    // Copy domain into the buffer
    char *ptr = buffer + sizeof(struct DNSHeader);
    char *domain_ptr = domain;
    while (*domain_ptr) {
        int len = strlen(domain_ptr);
        *ptr++ = len;
        memcpy(ptr, domain_ptr, len);
        ptr += len;
        domain_ptr += len + 1;
    }
    *ptr++ = 0;  // Null-terminate the domain string

    // Add DNS question (Type A, Class IN)
    struct DNSQuestion *dns_question = (struct DNSQuestion *)ptr;
    dns_question->qtype = htons(1);  // Type A
    dns_question->qclass = htons(1); // Class IN (Internet)
}

// Function to send a DNS query to a server and receive a response
void send_dns_query(char *domain) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    socklen_t len = sizeof(server_addr);

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set up the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER);

    // Build the DNS query
    build_query(buffer, domain);

    // Send DNS query to the server
    if (sendto(sockfd, buffer, sizeof(struct DNSHeader) + strlen(domain) + 2 + sizeof(struct DNSQuestion), 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Send failed");
        close(sockfd);
        exit(1);
    }

    // Receive DNS response
    int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &len);
    if (n < 0) {
        perror("Receive failed");
        close(sockfd);
        exit(1);
    }

    // Process the response (simplified for A record only)
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
    int offset = sizeof(struct DNSHeader) + strlen(domain) + 2 + sizeof(struct DNSQuestion);

    // Skip the answer section and get the address (Assume the answer is an A record)
    struct DNSRecord *dns_record = (struct DNSRecord *)(buffer + offset);
    if (ntohs(dns_record->type) == 1) {  // A record
        struct in_addr addr;
        addr.s_addr = dns_record->addr;
        printf("Resolved IP address for %s: %s\n", domain, inet_ntoa(addr));
    }

    close(sockfd);
}

int main() {
    char domain[256];

    // Get the domain to query
    printf("Enter the domain to query: ");
    scanf("%s", domain);

    // Send the DNS query to 1.1.1.1 and process the response
    send_dns_query(domain);

    return 0;
}

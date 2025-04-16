#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_PORT 4433
#define TLS_RECORD_HEADER_LENGTH 5


void print_bytes(uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t tls_record_header[TLS_RECORD_HEADER_LENGTH];
	size_t length_of_ServerHello;

    // Create TCP socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    // Prepare server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind socket to address
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_sock, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Server listening on port %d\n", SERVER_PORT);

    // Accept incoming connection
    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
        perror("accept");
        return 1;
    }

    printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Receive record header	
    if (recv(client_sock, tls_record_header, TLS_RECORD_HEADER_LENGTH, 0) != TLS_RECORD_HEADER_LENGTH) {
        perror("recv");
        return 1;
    }

    // Check content type (should be Handshake)
    if (tls_record_header[0] != 0x16) {
        printf("Invalid TLS record type\n");
        return 1;
    }

    // Calculate message length
    size_t message_length = (tls_record_header[3] << 8) + tls_record_header[4];

    // Allocate memory for the entire TLS record
    uint8_t *tls_record = (uint8_t *)malloc(message_length);

    // Receive the rest of the TLS record (ClientHello message)
    if (recv(client_sock, tls_record, message_length, 0) != message_length) {
        perror("recv");
        return 1;
    }

    // Print the received ClientHello message
    printf("Received TLS ClientHello message:\n");
    print_bytes(tls_record, message_length);

    /* 
	 * Add your code here for the ServerHello!
	 * 
     */
    size_t tls_server_hello_length = TLS_RECORD_HEADER_LENGTH + length_of_ServerHello;
    uint8_t *tls_server_hello = (uint8_t *)malloc(tls_server_hello_length);

    // Send ServerHello record in response
    if (send(client_sock, tls_server_hello, tls_server_hello_length, 0) < 0) {
        perror("send");
        return 1;
    }
	
    // Free allocated memory
    free(tls_record);

    // Close sockets
    close(client_sock);
    close(server_sock);

    return 0;
}
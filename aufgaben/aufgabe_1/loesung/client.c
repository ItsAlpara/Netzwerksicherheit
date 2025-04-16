#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 4433

void print_bytes(uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    uint8_t *tls_record;
    size_t tls_record_length;

    // Create TCP socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    // Prepare server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }


    /* 
	 * Add your code here to create a ClientHello
	 * 
	 */

	struct TLS_RECORD_LAYER{
		    uint8_t	  contentType;
		    uint16_t  version;
		    uint16_t  length;
	}__attribute__((__packed__));

	struct Handshake_Header{
		    uint8_t	  Type;
		    uint8_t	  length[3];
	};

        struct ClientHello{
    		uint16_t  ProtocolVersion;
		    uint8_t   Random[32];
		    uint8_t   legacy_session_id[32];
        	uint8_t   CipherSuite[2];
        	uint8_t   legacy_compression_methods;
        	uint8_t   extensions;
	};

    struct ClientHello CH = {
            .ProtocolVersion             = 0x304,
            .Random                      = { 0 },
            .legacy_session_id           = { 0 },
            .CipherSuite                 = { 0x13, 0x01 },
            .legacy_compression_methods  = 0,
            .extensions                  = 0
    };

    struct Handshake_Header HH = {
	        .Type	 = 0x01,
	        .length	 =  {   (sizeof(CH) >> 16) & 0xFF,
			                (sizeof(CH) >>  8) & 0xFF,
			                (sizeof(CH))  & 0xFF,
                        }
    };

	struct TLS_RECORD_LAYER RL = {
            .contentType    =       0x16,
            .version        =       htons(0x0304),
            .length         =       htons(sizeof(HH) + sizeof(CH))
    };
	


   	    tls_record_length = sizeof(CH)+sizeof(RL)+sizeof(HH);

    	tls_record = (uint8_t*) malloc(tls_record_length);

	    memcpy(tls_record             			        , &RL, sizeof(RL));
    	memcpy(tls_record + sizeof(RL)			        , &HH, sizeof(HH));
	    memcpy(tls_record + sizeof(RL) + sizeof(HH)	, &CH, sizeof(CH));
	

    // Print the generated ClientHello message
    printf("ClientHello message:\n");
    print_bytes(tls_record, tls_record_length);

    // Send the TLS record to the server
    if (send(sock, tls_record, tls_record_length, 0) < 0) {
        perror("send");
        return 1;
    }

    // Close socket
    close(sock);

    return 0;
}

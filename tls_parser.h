#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define NO_ERROR 0
#define INVALID_FILE_LENGTH 1
#define INVALID_CONTENT_TYPE 2
#define INVALID_VERSION 3
#define UNSUPPORTED_HANDSHAKE_MESSAGE_TYPE 4

typedef struct {
    uint8_t major;
    uint8_t minor;
} ProtocolVersion;

// All messages parseable using this parser should start with 0x16 indicating the hand-shake protocol
// Any other value is considered invalid
typedef enum {
    CHANGE_CIPHER_SPEC = 20,  // 0x14
    ALERT = 21,               // 0x15
    HANDSHAKE = 22,           // 0x16
    APPLICATION_DATA = 23,    // 0x17
} ContentType;

// This parser is capable of parsing messages 1, 2, 11, 12, 14 and 16
// Any other message is considered invalid
typedef enum {
    HELLO_REQUEST = 0,        // 0x00
    CLIENT_HELLO = 1,         // 0x01
    SERVER_HELLO = 2,         // 0x02
    CERTIFICATE = 11,         // 0x0B
    SERVER_KEY_EXCHANGE = 12, // 0x0C
    CERTIFICATE_REQUEST = 13, // 0x0D
    SERVER_HELLO_DONE = 14,   // 0x0E
    CERTIFICATE_VERIFY = 15,  // 0x0F
    CLIENT_KEY_EXCHANGE = 16, // 0x10
    FINISHED = 20,            // 0x14
} HandshakeType;

// This is how the message looks like as a whole (record layer + actual message)
typedef struct {
    ContentType cType;
    ProtocolVersion version;
    uint16_t fLength;         // Length of body + type (1 byte) + mLength (3 bytes)
    HandshakeType hsType;
    uint32_t mLength;         // Length of body
    unsigned char *body;      // We need to allocate "length" bytes at runtime
} HandshakeMessage;


typedef struct { 
	ProtocolVersion version;
	unsigned int sessionID;
	uint16_t ciSuiteLength;	
    	unsigned int compLength;
	unsigned int extLength;
    // RFC 5246 page 40
} ClientHello;

typedef struct {

	ProtocolVersion version;
	unsigned int sessionID;
	uint16_t ciSuiteLength;	
    	unsigned int compLength;
	unsigned int extLength;
    // Not implemented yet
    // RFC 5246 page 41
} ServerHello;
    
typedef struct {
    // Not implemented yet
    // RFC 5246 page 51
} ServerKeyExchange;

typedef struct {
    // Not implemented yet
    // RFC 5246 page 57
} ClientKeyExchange;

typedef struct { } Certificate;     // This message contains only a chain of certificates, which is not subject of parsing
typedef struct { } ServerHelloDone; // This message contains nothing, it's defined just for the sake of complentness

int initialize_tls_structure(unsigned char *raw, int size, HandshakeMessage *tls_message);
void print_tls_record_layer_info(HandshakeMessage *tls_message);

int parse_client_hello(unsigned char *message, uint16_t size);
int parse_server_hello(unsigned char *message, uint16_t size);
int parse_certificate(unsigned char *message, uint16_t size);
int parse_server_key_exchange(unsigned char *message, uint16_t size);
int parse_server_hello_done(unsigned char *message, uint16_t size);
int parse_client_key_exchange(unsigned char *message, uint16_t size);

// tls-parser.c : Defines the entry point for the console application.

#include "stdafx.h"
#include "stdint.h"
#include <stdlib.h>

#define NO_ERROR 0
#define INVALID_INPUT_FILE 1

typedef struct {
	uint8_t major;
    uint8_t minor;
} ProtocolVersion;

typedef enum {
		CHANGE_CIPHER_SPEC = 20, //0x14
		ALERT = 21, // x15
		// All messages parseable using this parser should start with 0x16 indicating the hand-shake protocol
		HANDSHAKE = 22, // 0x16
        APPLICATION_DATA = 23, // 0x17
		UNKNOWN = 255 // Any other value is illegal
} ContentType;

typedef struct {
          ContentType type;
          ProtocolVersion version;
          uint16_t length;
          unsigned char *fragment; // We need to allocate "length" bytes at runtime.
} TLSPlaintext;

errno_t initialize_tls_structure(unsigned char *raw, int size, TLSPlaintext *tls_message) {
	int i;

	if (size <= 4 || raw == NULL) {
		return INVALID_INPUT_FILE;
	}

	if (raw[0] != HANDSHAKE || raw[1] != 0x03) {
		return INVALID_INPUT_FILE;
	}

	tls_message->type = HANDSHAKE;
	tls_message->version.major = raw[1];
	
	if (raw[2] != 0x01 && raw[2] != 0x02 && raw[2] != 0x03) {
		return INVALID_INPUT_FILE;
	}

	tls_message->version.minor = raw[2];

	// Convert raw[3] and raw[4] to uint16_t number. 
	tls_message->length = 0;
	for (i = 3; i <= 4; i++) {
		tls_message->length = (tls_message->length << 8) | raw[i];
	}

	tls_message->fragment = raw + 5;

	return 0;
}

void print_tls_message(TLSPlaintext *tls_message) {
	int i;

	printf_s("Identified the following TLS message:\n\n");
	printf_s("TLS Version: ");
	switch (tls_message->version.minor) {
		case 0x01: printf_s("1.0\n"); break;
		case 0x02: printf_s("1.1\n"); break;
		case 0x03: printf_s("1.2\n"); break;
		default: printf_s("unknown\n");
	}
	printf_s("Message type: %d\n", tls_message->type);
	printf_s("Fragment length: %d\n", tls_message->length);
	printf_s("Fragment raw data: \n\n");

	for (i = 0; i < tls_message->length; i++) {
		printf_s("0x%x ", tls_message->fragment[i]); 
	}
	printf_s("\n");
}

int main(int argc, char* argv[]) {
	errno_t err;
	FILE *stream;
	unsigned char *buf;
	int file_size;
	TLSPlaintext tls_message;

	if (argc != 2) {
		printf_s("usage: %s\n", argv[0]);
		return 0;
	}

	stream = fopen(argv[1], "rb");
	if( stream == NULL ) {
		printf_s("The file '%s' couldn't be opened.\n", argv[1]);
		return 1;
	}

	// Get the actual file length
	fseek(stream, 0, SEEK_END);
	file_size = ftell(stream);
	fseek(stream, 0, SEEK_SET);

	buf = (unsigned char *)malloc(file_size);
	fread(buf, file_size, 1, stream);

	if (stream) {
		fclose(stream);
	}

	tls_message.fragment = (unsigned char *)malloc(file_size);
	err = initialize_tls_structure(buf, file_size, &tls_message);
	if (err != 0) {
		printf_s("There was an issue parsing this file. The issue is either malfored or not supported.\n");
	}

	print_tls_message(&tls_message);
	return 0;
}


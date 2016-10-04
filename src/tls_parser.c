#include "tls_parser.h"

int main(int argc, char* argv[]) {
    int err;

    // Check command line parameters and print usages in case they are not valid
    if (argc != 2) {
        printf("usage: %s\n", argv[0]);

        return 0;
    }

    // Try to open provided file
    FILE *stream;
    stream = fopen(argv[1], "rb");

    if (stream == NULL) {
        printf("The file '%s' couldn't be opened.\n", argv[1]);

        return 0;
    }

    // Get the actual file length
    fseek(stream, 0, SEEK_END);
    int file_size = ftell(stream);
    fseek(stream, 0, SEEK_SET);

    // Copy file content into buffer and close file stream
    unsigned char *buf;
    buf = (unsigned char *)malloc(file_size);
    fread(buf, file_size, 1, stream);

    if (stream) {
        fclose(stream);
    }

    // Parse the record layer headers and save the actual handshake message into tls_message->body
    HandshakeMessage tls_message;
    memset(&tls_message, 0, sizeof(tls_message));

    err = initialize_tls_structure(buf, file_size, &tls_message);

    // Close the original buffer containing the file stream, as all data has to be in tls_message
    if (buf) {
        free(buf);
    }

    // Stop processing in case there was an error
    handle_errors(err);

    print_tls_record_layer_info(&tls_message);

    // Process the actual handshake message
    switch (tls_message.hsType) {
        case 1: 
            err = parse_client_hello(tls_message.body, tls_message.mLength); break;
        case 2:
            err = parse_server_hello(tls_message.body, tls_message.mLength); break;
        case 11:
            err = parse_certificate(tls_message.body, tls_message.mLength); break;
        case 12: 
            err = parse_server_key_exchange(tls_message.body, tls_message.mLength); break;
        case 14:
            err = parse_server_hello_done(tls_message.body, tls_message.mLength); break;
        case 16:
            err = parse_client_key_exchange(tls_message.body, tls_message.mLength); break;
        default:
            printf("Unsupported handshake message type.\n");
            return 0;
    }

    handle_errors(err);

    printf("\nSuccesfully finished parsing of message!\n");

    return 0;
}

int initialize_tls_structure(unsigned char *raw, int size, HandshakeMessage *tls_message) {   
    // Handle length
    if (size <= 4 || raw == NULL) {
        return INVALID_FILE_LENGTH;
    }

    // Only handshake messages of TLS version 1.0 - 1.2 are allowed
    if (raw[0] != HANDSHAKE) {
        return INVALID_CONTENT_TYPE;
    }

    if (raw[1] != 0x03 || (raw[2] != 0x01 && raw[2] != 0x02 && raw[2] != 0x03)) {
        return INVALID_VERSION;
    }

    // Values are safe to assign to our structure
    tls_message->cType = HANDSHAKE;
    tls_message->version.major = raw[1];
    tls_message->version.minor = raw[2];

    // Convert raw[3] and raw[4] to uint16_t number
    tls_message->fLength = (raw[3] << 8) + raw[4];

    // Check if the sizes are correct (record protocol headers + length == file size)
    if (tls_message->fLength + 5 != size) {
        return INVALID_FILE_LENGTH;
    }

    // Does not need to check this value as the parser will not continue if this is not a supported handshake message type
    tls_message->hsType = raw[5];

    // Convert raw[6], raw[7] and raw[8] into uint24_t number
    // It's actually uint24_t but thats not defined
    tls_message->mLength = (0x00 << 24) + (raw[6] << 16) + (raw[7] << 8) + raw[8];

    // Check if the sizes are correct (fLength value == mLength value + HandshakeType (1 byte) + mLength (3 bytes))
    if (tls_message->fLength != tls_message->mLength + 4) {
        return INVALID_FILE_LENGTH;
    }

    // Copy the rest of the message into our structure, so we can close the raw stream
    tls_message->body = (unsigned char *)malloc(tls_message->mLength);
    memcpy(tls_message->body, raw + 9, tls_message->mLength);

    return 0;
}

void print_tls_record_layer_info(HandshakeMessage *tls_message) {
    printf("Identified the following TLS message:\n\n");
    printf("TLS Version: ");

    switch (tls_message->version.minor) {
        case 0x01: printf("1.0\n"); break;
        case 0x02: printf("1.1\n"); break;
        case 0x03: printf("1.2\n"); break;
        default: printf("unknown\n");
    }

    printf("Protocol type: %d\n", tls_message->cType);
    printf("Fragment length: %d\n", tls_message->fLength);
    printf("Handshake message type: %d\n", tls_message->hsType);
    printf("Handshake message length: %d\n\n", tls_message->mLength);

    // Uncomment for debugging purposes
    /*printf("Message raw data: \n\n");

    int i;
    for (i = 0; i < tls_message->mLength; i++) {
        printf("0x%x ", tls_message->body[i]); 
    }

    printf("\n");*/
}

int parse_client_hello(unsigned char *message, uint16_t size) {
    // Not implemented yet
    printf("1\n");
    return 0;
}

int parse_server_hello(unsigned char *message, uint16_t size) {
    // Not implemented yet
    printf("2\n");
    return 0;
}

int parse_certificate(unsigned char *message, uint16_t size) {
    // The Certificate message contains only a chain of certificates. 
    // The only thing to do is to verify, that the chain is not empty 
    // as we are not able to (and not supposed to) say anything about the data.
    if (size == 0) {
        return INVALID_FILE_LENGTH;
    }

    printf("The certificate chain provided is %d bytes long.\n", size);
    
    return 0;
}

int parse_server_key_exchange(unsigned char *message, uint16_t size) {
    // Not implemented yet
    printf("12\n");
    return 0;
}

int parse_server_hello_done(unsigned char *message, uint16_t size) {
    // The ServerHelloDone is empty. Just check if thats true.
    if (size != 0) {
        return INVALID_FILE_LENGTH;
    }

    return 0;
}

int parse_client_key_exchange(unsigned char *message, uint16_t size) {
    // Not implemented yet
    printf("16\n");
    return 0;
}

void handle_errors(int error_code) {
    if (!error_code) {
        // In case there is no error, continue.
        return;
    }

    printf("[ERROR]: ");

    switch (error_code) {
        case 1: printf("The lengths specified in the input file are not valid.\n"); break;
        case 2: printf("The input file is not an TLS handshake message.\n"); break;
        case 3: printf("The message is not of a supported version (TLS 1.0 - TLS 1.2).\n"); break;
        default:
            printf("Something truly unexpected happend.\n");
    }

    exit(0);
}
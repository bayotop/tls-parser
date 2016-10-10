#include "tls_parser.h"
#include <time.h>

#define bytes_to_u16(MSB,LSB) (((unsigned int) ((unsigned char) MSB)) & 255)<<8 | (((unsigned char) LSB)&255)


int main(int argc, char* argv[]) {
    	int err;

    	// Check command line parameters and print usages in case they are not valid
	// Minimum argument required is 2
    	if (argc != 2) {
        	printf("usage: %s\n", argv[0]);

       		return 0;
    	}

    	// Try to open provided file. Expected file is binary file
    	FILE *stream;
    	stream = fopen(argv[1], "rb");

    	if (stream == NULL) {
        	printf("The file '%s' couldn't be opened.\n", argv[1]);

        	return 1;
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
    	if (err != 0) {
        	printf("There was an issue parsing this file. The issue is either malfored or not supported.\n");

        	return err;
    	}

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
            		return UNSUPPORTED_HANDSHAKE_MESSAGE_TYPE;
    	}

	printf("The error code for debugging is %d\n",err);

    	if (err != 0) {
        	printf("There was an issue parsing this file. The issue is either malfored or not supported.\n");

        	return err;
    	}

    		printf("\nSuccesfully finished parsing of message!\n");

    	return 0;
}

int initialize_tls_structure(unsigned char *raw, int size, HandshakeMessage *tls_message) {   
    	// Handle length as expecting size greater than 4 bytes
    	if (size <= 4 || raw == NULL) {
        	return INVALID_FILE_LENGTH;
    	}

    	//MESSAGE TYPE VALIDATION-------------------------------------------------------------
	// The first byte value needs to be 0x16 for the message to be the handshake message
	// WHAT IF THE MALICIOUS CODE HAS THE FIRST BYTE AS 0x16 ??
    	
	if (raw[0] != HANDSHAKE) {
    	    return INVALID_CONTENT_TYPE;
    	}

	//MESSAGE TLS VERSION TYPE VALIDATION--------------------------------------------------
	// Only handshake messages of TLS version 1.0/1.1/1.2 are allowed ie 0x03 0x01/0x02/0x03
	//WHAT IF MALICIOUS CODE HAS VERSION AS 0x03 0x02 ??
    	
	if (raw[1] != 0x03 || (raw[2] != 0x01 && raw[2] != 0x02 && raw[2] != 0x03)) {
        	return INVALID_VERSION;
    	}

	
    	// Values are safe to assign to our structure after the validation of the message
    	tls_message->cType = HANDSHAKE;
    	tls_message->version.major = raw[1];
    	tls_message->version.minor = raw[2];

    	// Convert raw[3] and raw[4] to uint16_t number
	printf("3 : %d 4 : %d\n",raw[3],raw[4]);
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
	//We parse the body thereafter
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



int parse_client_hello(unsigned char *message, uint16_t size) {// Implementation started by Milan

	ClientHello C_Hello;
    	printf("THE DETAILS OF THE CLENT HELLO ARE AS UNDER :-\n");

	/*printf("---------------RAW DATA FOR CODING HELP START---------------------\n");
    	for (int i = 0; i < size; i++) {
        	printf("(%d)0x%x\n", i,message[i]);
		 
    	}
	printf("\n---------------RAW DATA FOR CODING HELP END-----------------------\n");*/

	//Action on first two bytes for version------------
	//Check if the versions are valid
	if (message[0] != 0x03 || (message[1] != 0x01 && message[1] != 0x02 && message[1] != 0x03)) {
        	return INVALID_VERSION;
    	}

	C_Hello.version.major = message[0];
	C_Hello.version.minor = message[1];
	
    	printf("TLS Client Hello Message Version (2 bytes): ");

    	switch (C_Hello.version.minor) {
        	case 0x01: printf("1.0\n"); break;
        	case 0x02: printf("1.1\n"); break;
        	case 0x03: printf("1.2\n"); break;
        	default: printf("unknown\n");
    	}
    	
	//Action on text 4 bytes are for timestamp-----------------

	unsigned int timestamp[4];

	printf("The time stamp is (4 bytes) : ");
	for(int i=2;i<=5;i++){
		timestamp[i-2] = message[i];
		printf("%d",timestamp[i]);
	
	}
	
	system ("date --date @$(printf '%d' 0x521dd201)");

	printf("\n");
	
	//Collect the random number of next 28 bytes

	unsigned int random[28];

	printf("The random number is (28 bytes) : ");
	for(int i=6;i<=33;i++){
		random[i-6] = message[i];
		printf("%x",random[i]);
	}
	printf("\n");
	// Next is one byte session ID
	
	C_Hello.sessionID = message[34];
	printf("The session ID is (1 byte) : %d\n", C_Hello.sessionID);

	//Finding the cipher suite length next 2 bytes

	C_Hello.ciSuiteLength = (message[35] << 8) + message[36];
	printf("The cipher suite length is (2 bytes) : %d\n", C_Hello.ciSuiteLength);

	//List the cipher suites
	printf("Total No of cipher suits are : %d\n", (C_Hello.ciSuiteLength/2));
	unsigned int cisuite[C_Hello.ciSuiteLength];
	printf("The cipher suite codes are (each 2 bytes) : ");
	for(int i=0;i<C_Hello.ciSuiteLength; i++){
		cisuite[i] = message[i+37];
		printf("%x ",cisuite[i]);
	}
	printf("\n");

	//List the compression method lengths

	C_Hello.compLength = message[36 + C_Hello.ciSuiteLength + 1]; // 71 for our test case
	printf("The compression method length is (1 byte) : %d\n", C_Hello.compLength);
	

	// List the compresion methods (each 1 byte)

	int startByteCompMethod = (36 + C_Hello.ciSuiteLength + 2);

	unsigned int compMethod[C_Hello.compLength];
	printf("The comp method codes are (each 1 bytes) : ");
	for(int i=0;i<C_Hello.compLength; i++){
		compMethod[i] = message[i + startByteCompMethod];
		printf("%x  ",compMethod[i]);
	}
	printf("\n");

	// Find the extension length
	
	C_Hello.extLength = (message[startByteCompMethod + C_Hello.compLength] << 8) + message[startByteCompMethod + C_Hello.compLength+1];
	printf("The extension length is (2 bytes) : %d\n", C_Hello.extLength);
	return 0;
}

int parse_server_hello(unsigned char *message, uint16_t size) {// Implementation started by Milan

	ServerHello S_Hello;
    	printf("THE DETAILS OF THE SERVER HELLO ARE AS UNDER :-\n");

	/*printf("---------------RAW DATA FOR CODING HELP START---------------------\n");
    	for (int i = 0; i < size; i++) {
        	printf("(%d)0x%x\n", i,message[i]);
		 
    	}
	printf("\n---------------RAW DATA FOR CODING HELP END-----------------------\n");*/

	//Action on first two bytes for version------------
	//Check if the versions are valid
	if (message[0] != 0x03 || (message[1] != 0x01 && message[1] != 0x02 && message[1] != 0x03)) {
        	return INVALID_VERSION;
    	}

	S_Hello.version.major = message[0];
	S_Hello.version.minor = message[1];
	
    	printf("TLS Server Hello Message Version (2 bytes): ");

    	switch (S_Hello.version.minor) {
        	case 0x01: printf("1.0\n"); break;
        	case 0x02: printf("1.1\n"); break;
        	case 0x03: printf("1.2\n"); break;
        	default: printf("unknown\n");
    	}
    	
	//Action on text 4 bytes are for timestamp-----------------

	unsigned int timestamp[4];

	printf("The time stamp is (4 bytes) : ");
	for(int i=2;i<=5;i++){
		timestamp[i-2] = message[i];
		printf("%d",timestamp[i]);
	
	}
	
	system ("date --date @$(printf '%d' 0x521dd201)");

	printf("\n");
	
	//Collect the random number of next 28 bytes

	unsigned int random[28];

	printf("The random number is (28 bytes) : ");
	for(int i=6;i<=33;i++){
		random[i-6] = message[i];
		printf("%x",random[i]);
	}
	printf("\n");
	// Next is one byte session ID
	
	S_Hello.sessionID = message[34];
	printf("The session ID is (1 byte) : %d\n", S_Hello.sessionID);

	
	//List the cipher suites
	
	unsigned int cisuite[2];

	cisuite[0] = message[35];
	cisuite[1] = message[36];
	printf("The cipher suite accepted code is (each 2 bytes) : %x %x\n",cisuite[0],cisuite[1] );
	
	//List the compression method lengths

	
	unsigned int compMethod[1];
	compMethod[0] = message[37];
	printf("The comp method code is (each 1 bytes) : %x\n",compMethod[0] );
	

	// Find the extension length
	
	S_Hello.extLength = (message[38] << 8) + message[39];
	printf("The extension length is (2 bytes) : %d\n", S_Hello.extLength);
    	
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

int parse_server_key_exchange(unsigned char *message, uint16_t size)
{

    	ServerKeyExchange severKeyExchange;
    	uint16_t length;
    	uint16_t indexOfProcessedByte=0;

    	if(message[0]!=0x0C)
    	{
        	return UNSUPPORTED_HANDSHAKE_MESSAGE_TYPE;
    	}

    	//incase of DHE_RSA, DHE_DSS, DH_ANON next three byte is length
    	//????
    	// Convert raw[1], raw[2] and raw[3] into uint24_t number
    	severKeyExchange.mLength = (0x00 << 24) + (message[1] << 16) + (message[2]<< 8) + message[3];
    	length=severKeyExchange.mLength ;
    	indexOfProcessedByte+=3;

    	//next two bytes are for p length
    	length-=2;
    	severKeyExchange.params.length_dh_p = (0x00 <<8) + (message[4] << 8) + message[5];
    	indexOfProcessedByte+=2;
    	length-=severKeyExchange.params.length_dh_p;
    	if(length<0)
    	{
        	return INVALID_FILE_LENGTH;
    	}

    	//next severKeyExchange.params.length_dh_p bytes are for p
    	indexOfProcessedByte+=severKeyExchange.params.length_dh_p;

    	//next two bytes are for g length
    	length-=2;
    	severKeyExchange.params.length_dh_g = (0x00 << 8) + (message[indexOfProcessedByte] << 8) + message[indexOfProcessedByte+1];
    	indexOfProcessedByte+=2;
    	length-=severKeyExchange.params.length_dh_g;
    	if(length<0)
    	{
        	return INVALID_FILE_LENGTH;
    	}

    	//next severKeyExchange.params.length_dh_g bytes are for g
    	indexOfProcessedByte+=severKeyExchange.params.length_dh_g;

    	//next two bytes are for pubkey length
    	length-=2;
    	severKeyExchange.params.length_dh_ys = (0x00 << 8) + (message[indexOfProcessedByte] << 8) + message[indexOfProcessedByte+1];
    	indexOfProcessedByte+=2;
    	length-=severKeyExchange.params.length_dh_ys;
    	if(length<0)
    	{
        	return INVALID_FILE_LENGTH;
    	}

    	//next severKeyExchange.params.length_dh_ys bytes are for pubkey
    	indexOfProcessedByte+=severKeyExchange.params.length_dh_ys;

    	//in case of dhe_dss and dhe_rsa KeyExchangeAlgorithms, there are
	//additional byte for signiture and signiture hash algorithm
    	//??????????????

    	return 0;
}


int parse_client_key_exchange(unsigned char *message, uint16_t size)
{

    	ClientKeyExchange clientKeyExchange;
    	uint16_t length;

    	if(message[0]!=0x16)
    	{
        	return UNSUPPORTED_HANDSHAKE_MESSAGE_TYPE;
    	}

    	uint16_t indexOfProcessedByte=0;

    	//next two bytes are for pubkey length
    	length-=2;
    	clientKeyExchange.pubKeyLength = (0x00 << 8) + (message[indexOfProcessedByte] << 8) + message[indexOfProcessedByte+1];
    	indexOfProcessedByte+=2;
    	length-=clientKeyExchange.pubKeyLength;
    	if(length<0)
    	{
        	return INVALID_FILE_LENGTH;
    	}

    	return 0;
}

int parse_server_hello_done(unsigned char *message, uint16_t size) {
    // The ServerHelloDone is empty. Just check if thats true.
    if (size != 0) {
        return INVALID_FILE_LENGTH;
    }

    return 0;
}

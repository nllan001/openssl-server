#include "string.h"
#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#define RAND_NUM 1024

RSA *setUpRSA(unsigned char *key, int public) {
    RSA *rsa = NULL;
    BIO *bio;
    if(!(bio = BIO_new_mem_buf(key, -1))) {
        printf("Error setting up bio\n");
        return NULL;
    }
    if(public) {
        rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    }
    if(!rsa) {
        printf("Error setting up rsa\n");
    }
    BIO_free(bio);
    return rsa;
}

void send(SSL *serverSSL) {
		int pathLength = 64;
		char fileName[pathLength];
		bzero(fileName, pathLength);
		int read = SSL_read(serverSSL, fileName, pathLength);
		if(read < 0) {
				ERR_print_errors_fp(stderr);
				return;
		}

		char *fileBuf = 0;
		long fileLength;
		FILE *file = fopen(fileName, "rb");
		if(file) {
				fseek(file, 0, SEEK_END);
				fileLength = ftell(file);
				fseek(file, 0, SEEK_SET);
				fileBuf = malloc(fileLength);
				if(fileBuf) {
						fread(fileBuf, 1, fileLength, file);
				} else {
						printf("Error reading file.\n");
						return;
				}
		} else {
				printf("Error opening file.\n");
				return;
		}
		fileBuf[fileLength] = '\0';
		printf("%s\n", fileBuf);
}

void receive(SSL *serverSSL) {
		int pathLength = 64;
		char fileName[pathLength];
		bzero(fileName, pathLength);
		int read = SSL_read(serverSSL, fileName, pathLength);
		if(read < 0) {
				ERR_print_errors_fp(stderr);
				return;
		}

		char directory[32] = "./serverFiles/";
		strcat(directory, fileName);
		printf("%s\n", directory);
		FILE *file = fopen(directory, "wb");
}

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Not enough arguments.");
        return -1;
    } else if(argc > 2) {
        printf("Too many arguments.");
        return -1;
    }

    char *portNum = argv[1];

    portNum = strcpy(portNum, strchr(portNum, '=') + 1);

    /* read in private key */
    char *private;
    FILE *privFile;
    long size;
    char *mode = "rb";

    privFile = fopen("private.pem", mode);

    fseek(privFile, 0L, SEEK_END);
    size = ftell(privFile);
    rewind(privFile);

    private = calloc(1, size + 1);
    fread(private, size, 1, privFile);

    fclose(privFile);

    /* initialize ssl */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* set up the context */
    SSL_CTX *serverCTX = SSL_CTX_new(SSLv23_server_method());
    if(!serverCTX) {
        printf("Failed to create SSL CTX\n");
        return -1;
    }

		/* set up diffie helman parameters */
    DH *diffie = DH_new();
    DH_generate_parameters_ex(diffie, 256, 2, NULL);
    DH_generate_key(diffie);

    /* set cipher list */
    SSL_CTX_set_cipher_list(serverCTX, "EXP-ADH-RC4-MD5");
    SSL_CTX_set_tmp_dh(serverCTX, diffie);

    /* create new ssl */
    SSL *serverSSL = SSL_new(serverCTX);
    if(!serverSSL) {
        printf("Failed to create SSL\n");
        return -1;
    }

    /* set up the read and write bios and blocking status */
    BIO *bio = BIO_new(BIO_s_accept());;
    BIO_set_accept_port(bio, portNum);

    /* connect the bios */
    int acc;
    if((acc = BIO_do_accept(bio)) <= 0) {
        printf("Failed to accept bio. %d.\n", SSL_get_error(serverSSL, acc));
    } else {
        printf("Accepting...\n");
    }

    /* set the ssl to use the new bios */
    SSL_set_bio(serverSSL, bio, bio);
    /* accept connections */
    int accept = SSL_accept(serverSSL);

    /* read encrypted challenge from client */
    int randNum = 2048;
    char encryptedBuf[randNum];
    bzero(encryptedBuf, randNum);
    int read = SSL_read(serverSSL, encryptedBuf, randNum);
    if(read < 0) {
        ERR_print_errors_fp(stderr);
    }
    //printf("Encrypted: \n%s\n", encryptedBuf);

    /* decrypt the challenge */
		int dLength = 128;
    char decrypted[128];
		bzero(decrypted, dLength);
    int pad = RSA_NO_PADDING;
    RSA *privrsa = setUpRSA(private, 0);
    int privDecrypt = RSA_private_decrypt(dLength, encryptedBuf, decrypted, privrsa, pad);
    if(privDecrypt < 0) {
        ERR_print_errors_fp(stderr);
    }

		/* hash the client's message */
		int hashSize = 20;
		unsigned char shaBuf[hashSize];
		bzero(shaBuf, hashSize);
		unsigned char *hash = SHA1(decrypted, dLength, shaBuf);
		shaBuf[hashSize] = '\0';
//		printf("Hash: %s\n", shaBuf);

		/* encrypt the hashed message */
		unsigned char encrypted[2048] = {};
		pad = RSA_PKCS1_PADDING;
		int privEncrypt = RSA_private_encrypt(hashSize, shaBuf, encrypted, privrsa, pad);
		if(privEncrypt < 0) {
				ERR_print_errors_fp(stderr);
		}
printf("length: %d, size: %d\n", strlen(encrypted), RSA_size(privrsa));

		//printf("encrypted: %s\n", encrypted);

    /* write to client */
    int write = SSL_write(serverSSL, encrypted, 2048);
    if(write < 0) {
        ERR_print_errors_fp(stderr);
    }

		/* receive option flag from client */
		char options[32];
		bzero(options, 32);
		read = SSL_read(serverSSL, options, 32);
		if(read < 0) {
				ERR_print_errors_fp(stderr);
		}

    /* send and receive check */
    char *s = "send";
    char *r = "receive";
    if(!strcmp(options, s)) {
				receive(serverSSL);
    } else if(!strcmp(options, r)) {
				send(serverSSL);
    } else {
				printf("Incorrect option received: %s\n", options);
				SSL_shutdown(serverSSL);
				return 0;
		}

    /* shutdown ssl and free bio */
    SSL_shutdown(serverSSL);
    return 0;
}

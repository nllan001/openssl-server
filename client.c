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
    return rsa;
}



int main(int argc, char **argv) {
    if(argc < 5) {
        printf("Not enough arguments.");
        return -1;
    } else if(argc > 5) {
        printf("Too many arguments.");
        return -1;
    }

    char *hostName = argv[1];
    char *portNum = argv[2];
    char *option = argv[3] + 2;
    char *fileName = argv[4];

    hostName = strcpy(hostName, strchr(hostName, '=') + 1);
    portNum = strcpy(portNum, strchr(portNum, '=') + 1);

    /* read in public key */
    char *public;
    FILE *pubFile;
    long size;
    char *mode = "rb";

    pubFile = fopen("public.pem", mode);
    fseek(pubFile, 0L, SEEK_END);
    size = ftell(pubFile);
    rewind(pubFile);
    public = calloc(1, size + 1);
    fread(public, size, 1, pubFile);
    fclose(pubFile);

    /* generate prn */
    int randNum = 128;
    char randBuf[128];
    bzero(randBuf, randNum);
    unsigned char seedBuf[randNum];
    RAND_seed(seedBuf, randNum);
    int randError = RAND_bytes(randBuf, randNum);
		randBuf[randNum] = '\0';
    if(!randError) {
        printf("Error with generating cryptographic PRN\n");
        return -1;
    }

		/* hash the prn to later compare against the server's response */
		unsigned char shaBuf[20];
		bzero(shaBuf, 20);
		unsigned char *hash = SHA1(randBuf, randNum, shaBuf);

    /* encrypt challenge with server's public key */
    unsigned char encrypted[2048] = {};
    int pad = RSA_NO_PADDING;
    RSA *pubrsa = setUpRSA(public, 1);
    int pubEncrypt = RSA_public_encrypt(randNum, randBuf, encrypted, pubrsa, pad);
    while(pubEncrypt < 0) {
        //ERR_print_errors_fp(stderr);
				bzero(encrypted, 2048);
    		pubEncrypt = RSA_public_encrypt(randNum, randBuf, encrypted, pubrsa, pad);
    }

    /* initialize ssl */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

		/* set up context */
    SSL_CTX *clientCTX = SSL_CTX_new(SSLv23_client_method());
    if(!clientCTX) {
        printf("Failed to create SSL CTX\n");
        return -1;
    }

    /* set cipher list */
    SSL_CTX_set_cipher_list(clientCTX, "EXP-ADH-RC4-MD5");

    /* create new ssl */
    SSL *clientSSL = SSL_new(clientCTX);
    if(!clientSSL) {
        printf("Failed to create SSL\n");
        return -1;
    }

    /* set up the read and write bios */
    BIO *bio = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(bio, hostName);
    BIO_set_conn_port(bio, portNum);

    /* connect the bios */
    if(BIO_do_connect(bio) <= 0) {
        printf("Failed to connect bio.\n");
    }

    /* set the ssl to use the new bios */
    SSL_set_bio(clientSSL, bio, bio);

    /* start connections */
    int connect = SSL_connect(clientSSL);

    /* write to server */
    int write = SSL_write(clientSSL, encrypted, randNum);
    if(write < 0) {
        ERR_print_errors_fp(stderr);
    }

		/* read encrypted hashed response from server */
		unsigned char encryptedHash[2048];
		int read = SSL_read(clientSSL, encryptedHash, 2048);
		if(read < 0) {
        ERR_print_errors_fp(stderr);
		}

		/* decrypt response */
		pad = RSA_PKCS1_PADDING;
		unsigned char decryptedHash[20];
//printf("length: %d, size: %d\n", strlen(encryptedHash), RSA_size(pubrsa));
		int pubDecrypt = RSA_public_decrypt(strlen(encryptedHash), encryptedHash, decryptedHash, pubrsa, pad);
		while(pubDecrypt < 0) {
				//ERR_print_errors_fp(stderr);
				pubDecrypt = RSA_public_decrypt(strlen(encryptedHash), encryptedHash, decryptedHash, pubrsa, pad);
		}

		/* authenticate the server's response */
		decryptedHash[20] = '\0';
		if(!strcmp(decryptedHash, hash)) {
				printf("Successful Authentication.\n");
		} else {
				printf("Authentication Failed.\n");
				SSL_shutdown(clientSSL);
				return 0;
		}

		/* send option flag */
		write = SSL_write(clientSSL, option, strlen(option));
		if(write < 0) {
				ERR_print_errors_fp(stderr);
		}

    SSL_shutdown(clientSSL);
    return 0;
}

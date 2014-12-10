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
    char *option = argv[3];
    char *fileName = argv[4];
    int pad = RSA_PKCS1_PADDING;

    hostName = strcpy(hostName, strchr(hostName, '=') + 1);
    portNum = strcpy(portNum, strchr(portNum, '=') + 1);
    option = strcpy(option, strchr(option, '-') + 2);

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
    unsigned char buf[RAND_NUM];
    unsigned char seedBuf[RAND_NUM];
    bzero(buf, RAND_NUM);
    RAND_seed(seedBuf, RAND_NUM);
    int randError = RAND_bytes(buf, RAND_NUM);
    if(!randError) {
        printf("Error with generating cryptographic PRN\n");
        return -1;
    }

    /* encrypt challenge with server's public key */
    unsigned char encrypted[4096] = {};
    RSA *pubrsa = setUpRSA(public, 1);
    int pubEncrypt = RSA_public_encrypt(strlen(buf), buf, encrypted, pubrsa, pad);

    /* set up socket */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *clientCTX = SSL_CTX_new(TLSv1_1_client_method());
    if(!clientCTX) {
        printf("Failed to create SSL CTX\n");
        return -1;
    }

    /* create new ssl */
    SSL *clientSSL = SSL_new(clientCTX);
    if(!clientSSL) {
        printf("Failed to create SSL\n");
        return -1;
    }

    /* set up the read and write bios */
    BIO *rbio, *wbio;
    rbio = BIO_new_connect(hostName);
    wbio = BIO_new_connect(hostName);
    BIO_set_conn_port(rbio, portNum);
    BIO_set_conn_port(wbio, portNum);

    /* connect the bios */
    if(BIO_do_connect(rbio) <= 0) {
        printf("Failed to connect read bio.\n");
    }
    if(BIO_do_connect(wbio) <= 0) {
        printf("Failed to connect write bio.\n");
    }

    /* set the ssl to use the new bios */
    SSL_set_bio(clientSSL, rbio, wbio);

    /* start connections */
    int connect = SSL_connect(clientSSL);

    return 0;
}

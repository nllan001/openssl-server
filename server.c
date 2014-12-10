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
    SSL_CTX *serverCTX = SSL_CTX_new(TLSv1_1_server_method());
    if(!serverCTX) {
        printf("Failed to create SSL CTX\n");
        return -1;
    }

    SSL_CTX_set_cipher_list(serverCTX, "ADH");

    /* create new ssl */
    SSL *serverSSL = SSL_new(serverCTX);
    if(!serverSSL) {
        printf("Failed to create SSL\n");
        return -1;
    }

    /* set up the read and write bios and blocking status */
    BIO *bio;
    bio = BIO_new_accept(portNum);

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
    SSL_set_accept_state(serverSSL);
    int handshake = SSL_do_handshake(serverSSL);

    /* read from client */
    char options[10];
    bzero(options, 10);
    int read = SSL_read(serverSSL, options, 10);
    if(read < 0) {
        ERR_print_errors_fp(stderr);
    }
    printf("%d\n", read);

    /* shutdown ssl and free bio */
    BIO_free(bio);
    SSL_shutdown(serverSSL);
    return 0;
}


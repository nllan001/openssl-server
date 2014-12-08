#include "string.h"
#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#define RAND_NUM 1024

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

    hostName = strcpy(hostName, strchr(hostName, '=') + 1);
    portNum = strcpy(portNum, strchr(portNum, '=') + 1);
    option = strcpy(option, strchr(option, '-') + 2);

    unsigned char buf[RAND_NUM];
    bzero(buf, RAND_NUM);
    RAND_seed(buf, RAND_NUM);
    int randError = RAND_bytes(buf, RAND_NUM);
    if(!randError) {
        printf("Error with generating cryptographic PRN");
        return -1;
    }

    return 0;
}

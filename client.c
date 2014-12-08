#include "string.h"
#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"

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
}

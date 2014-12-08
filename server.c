#include "string.h"
#include "stdio.h"

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Not enough arguments.");
        return -1;
    } else if(argc > 2) {
        printf("Too many arguments.");
        return -1;
    }

    char *portNum = argv[1];
}

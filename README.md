openssl-server
==============

To generate private key and put in file mykey.pem:
openssl genrsa -out mykey.pem 1024

To extract public key:
openssl rsa -in mykey.pem -pubout > mykey.pub

openssl-server
==============

To generate private key and put in file mykey.pem:
openssl genrsa -out private.pem 1024

To extract public key:
openssl rsa -in private.pem -pubout > public.pem

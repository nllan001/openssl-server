all: client server

client: client.c
	gcc-4.9 client.c -o client -L./openssl -lssl -lcrypto -ldl

server: server.c
	gcc-4.9 server.c -o server -L./openssl -lssl -lcrypto -ldl

clean:
	rm server client

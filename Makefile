all: client server

runc: client
	client --serverAddress=1104.236.53.95 --port=20193 --send ./file

runs: server
	server --port=20193

client: client.c
	gcc-4.9 client.c -o client -L./openssl -lssl -lcrypto -ldl

server: server.c
	gcc-4.9 server.c -o server -L./openssl -lssl -lcrypto -ldl

clean:
	rm server client

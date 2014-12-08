all: client server

client: client.c
	gcc-4.9 client.c -o client

server: server.c
	gcc-4.9 server.c -o server

clean:
	rm server client

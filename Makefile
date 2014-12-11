PORT=20194
all: client server

runc: client
	./client --serverAddress=localhost --port=$(PORT) --receive ./file

runs: server
	./server --port=$(PORT)

client: client.c
	gcc client.c -o client -lssl -lcrypto -ldl

server: server.c
	gcc server.c -o server -lssl -lcrypto -ldl

clean:
	rm server client

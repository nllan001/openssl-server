PORT = 20193
#HOST = localhost
HOST = 169.235.30.192
all: client server

runc: client
	./client --serverAddress=$(HOST) --port=$(PORT) --receive ./send.txt

runs: server
	./server --port=$(PORT)

client: client.c
	gcc client.c -o client -lssl -lcrypto -ldl

server: server.c
	gcc server.c -o server -lssl -lcrypto -ldl

setup:
	mkdir clientFiles
	mkdir serverFiles

clean:
	rm server client

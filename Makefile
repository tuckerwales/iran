CC=gcc
CFLAGS=-I/opt/homebrew/include/ -L/opt/homebrew/lib/ -lusb-1.0 -lcrypto

.SILENT: iran clean
	
iran: main.o
	$(CC) *.o $(CFLAGS) -o iran

clean:
	rm -f *.o iran


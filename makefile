interface.o: socket/interface.c
	gcc -c socket/interface.c

sock.o: socket/sock.c
	gcc -c socket/sock.c

dns_sniff.o: dns_sniff.c
	gcc -c dns_sniff.c

install: interface.o sock.o dns_sniff.o 
	gcc -o dns_sniff *.o
	$(MAKE) clean

clean: 
	rm -rf *.o 
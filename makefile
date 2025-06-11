LDLIBS=-lpcap

all: tls-block

main.o: mac.h ip.h ethhdr.h iphdr.h tcphdr.h main.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tls-block: main.o tcphdr.o iphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tls-block *.o

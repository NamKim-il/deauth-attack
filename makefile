LDLIBS=-lpcap

all: deauth-attack 

deauth-attack: main.o mac.o deauth.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o 

CFLAGS=-g

stalk : stalk.o proto.o rc4.o
	cc $(CFLAGS) -lcrypto -lpthread -o stalk stalk.o proto.o rc4.o
	
stalk.o : stalk.c stalk.h
	cc $(CFLAGS) -c stalk.c
	
#proto : proto.o rc4.o
#	cc $(CFLAGS) -lcrypto -o proto proto.o rc4.o

proto.o : proto.c proto.h
	cc $(CFLAGS) -c proto.c

#rc4 : rc4.c rc4.h
#	cc $(CFLAGS) rc4.c -o rc4
	
rc4.o : rc4.c rc4.h
	cc $(CFLAGS) -c rc4.c
	
clean :
	rm rc4.o stalk proto rc4 stalk.o proto.o

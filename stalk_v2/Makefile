CFLAGS=-g

stalk2 : stalk2.o proto2.o rc4strong.o
	cc $(CFLAGS) -lcrypto -lpthread -o stalk2 stalk2.o proto2.o rc4strong.o
	
stalk2.o : stalk2.c stalk2.h
	cc $(CFLAGS) -c stalk2.c
	
proto2 : proto2.o rc4strong.o
	cc $(CFLAGS) -lcrypto -o proto2 proto2.o rc4strong.o

proto2.o : proto2.c proto2.h
	cc $(CFLAGS) -c proto2.c

#rc4strong : rc4strong.c rc4strong.h
#	cc $(CFLAGS) -lcrypto rc4strong.c -o rc4strong
	
rc4strong.o : rc4strong.c rc4strong.h
	cc $(CFLAGS) -c rc4strong.c
	
clean :
	rm rc4strong.o stalk2 stalk2.o proto2.o

CC=g++
CFLAGS=-Wall -O2 -Wno-deprecated
LDFLAGS=-lkeyczar_base -lkeyczar -lcrypto -licuuc -lrt -lpthread
PROG= testdata_gen basic_encrypt basic_sign

all: $(PROG)

%: %.cc
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) $(filter %.cc,$^)

clean:
	rm -f *.o $(PROG) *~ *#

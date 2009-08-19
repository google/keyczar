CC=g++
CFLAGS=-W -Wall -O2
# Append to the line below:
# On BSD: -L/usr/local/lib -I/usr/local/include
LDFLAGS=-lkeyczar -lcrypto

PROG= 	testdata_gen \
	basic_encrypt \
	basic_sign \
	encrypt_file \
	keyczar_tool \
	pbe_encrypt

all: $(PROG)

%: %.cc
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) $(filter %.cc,$^)

clean:
	rm -f *.o $(PROG) *~ *#

CC=g++
CFLAGS=-Wall -O2
# Append to the line below:
# On BSD: -L/usr/local/lib -I/usr/local/include
# On MacOSX you might need: -L/opt/local/lib (for icu)
LDFLAGS=-lkeyczar -lcrypto -licuuc
PROG= testdata_gen basic_encrypt basic_sign

all: $(PROG)

%: %.cc
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) $(filter %.cc,$^)

clean:
	rm -f *.o $(PROG) *~ *#

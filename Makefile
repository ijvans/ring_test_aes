
.PHONY: all clean

all: rtaes

aes.o: aes.c aes.h
	gcc -c -std=c99 -o aes.o aes.c

proc.o: proc.c aes.h rtaes.h
	gcc -c -std=c99 -o proc.o proc.c

main.o: main.c rtaes.h
	gcc -c -std=c99 -o main.o main.c

rtaes: main.o proc.o aes.o
	gcc -o rtaes main.o proc.o aes.o

clean:
	rm -f *.o rtaes
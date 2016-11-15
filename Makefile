CC = g++
CFLAGS = --std=c++11

all: main

main: main.o radiotap.o mac.o
	$(CC) $(CFLAGS) main.o radiotap.o mac.o -o main -lpcap

radiotap.o: radiotap.cpp radiotap.h
	$(CC) $(CFLAGS) -c radiotap.cpp

mac.o: mac.cpp mac.h radiotap.h
	$(CC) $(CFLAGS) -c mac.cpp

main.o: main.cpp mac.h radiotap.h
	$(CC) $(CFLAGS) -c main.cpp

clean:
	\rm -f *.o main
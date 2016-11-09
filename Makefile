CC = /usr/local/linaro/arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++
CFLAGS = -Wall --std=c++11

all: main

main: main.o
	$(CC) $(CFLAGS) main.o -o main

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

clean:
	\rm -f *.o main
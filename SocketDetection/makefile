CC = GCC # Flag for implicit rules
TARGET = SocketEncrypt
INCLUDE = /usr/local/include
INCLUDE1 = ./include
LIBS = /usr/local/lib
LIB1 = gtest
LIB2 = gtest_main

$(TARGET): SocketEncrypt.o
	$(CC) -I $(INCLUDE) -I $(INCLUDE1) -L$(LIBS) -l$(LIB1) -l$(LIB2) -o $(TARGET) SocketEncrypt.o

SocketEncrypt.o: ./SocketEncrypt.cpp
	$(CC) -I $(INCLUDE) -I $(INCLUDE1) -c ./SocketEncrypt.cpp -o SocketEncrypt.o

clean:
	rm *.o finished
CC = gcc # Flag for implicit rules
flags = -g
TARGET = SocketEncrypt
INCLUDE = /usr/local/include
LIBS = /usr/local/lib

$(TARGET): EncryptionProbe.o
	$(CC) -I $(INCLUDE) $(flags) -L$(LIBS) -o $(TARGET) EncryptionProbe.o

EncryptionProbe.o: ./EncryptionProbe.cpp
	$(CC) -I $(INCLUDE) $(flags) -o EncryptionProbe.o -c ./EncryptionProbe.cpp 

clean:
	rm *.o finished
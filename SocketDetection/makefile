CC = gcc # Flag for implicit rules
flags = -g
TARGET = SocketEncrypt
INCLUDE = /usr/local/include
LIBS = /usr/local/lib

$(TARGET): EncryptionProbe.o
	$(CC) -I $(INCLUDE) $(flags) -L$(LIBS) -o $(TARGET) EncryptionProbe.o

EncryptionProbe.o: ./EncryptionProbe.c
	$(CC) -I $(INCLUDE) $(flags) -o EncryptionProbe.o -c ./EncryptionProbe.c

clean:
	rm *.o finished
CC     = g++
CFLAGS = -Wall -Wextra -O2 -std=gnu17 -g
LFLAGS =

.PHONY: all clean

TARGET1 = ppcbc
TARGET2 = ppcbs

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(TARGET1).o common.o protocol.o Client.o ClientUDP.o
	$(CC) $(LFLAGS) -o $@ $^
$(TARGET2): $(TARGET2).o common.o protocol.o ServerUDP.o Server.o
	$(CC) $(LFLAGS) -o $@ $^

# To są zależności wygenerowane automatycznie za pomocą polecenia `gcc -MM *.c`.
Client.o: Client.cpp Client.h protocol.h protconst.h common.h
ClientUDP.o: ClientUDP.cpp ClientUDP.h Client.h protocol.h protconst.h \
 common.h
Server.o: Server.cpp Server.h protocol.h protconst.h common.h
ServerUDP.o: ServerUDP.cpp ServerUDP.h Server.h protocol.h protconst.h \
 common.h
common.o: common.cpp common.h
ppcbc.o: ppcbc.cpp common.h protocol.h protconst.h
ppcbs.o: ppcbs.cpp common.h protocol.h protconst.h ServerUDP.h Server.h
protocol.o: protocol.cpp protocol.h protconst.h common.h

clean:
	rm -f $(TARGET1) $(TARGET2) *.o *~
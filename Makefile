CC     = g++
CFLAGS = -Wall -Wextra -O2 -std=gnu17
LFLAGS =

.PHONY: all clean

TARGET1 = ppcbc
TARGET2 = ppcbs

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(TARGET1).o err.o common.o
	$(CC) $(LFLAGS) -o $@ $^
$(TARGET2): $(TARGET2).o err.o common.o ServerUDP.o Server.o
	$(CC) $(LFLAGS) -o $@ $^

# To są zależności wygenerowane automatycznie za pomocą polecenia `gcc -MM *.c`.
Server.o: Server.cpp Server.h err.h
ServerUDP.o: ServerUDP.cpp ServerUDP.h Server.h
common.o: common.cpp err.h common.h
err.o: err.cpp err.h
ppcbc.o: ppcbc.cpp err.h common.h protocol.h protconst.h

clean:
	rm -f $(TARGET1) $(TARGET2) *.o *~
CC     = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu17
LFLAGS =

.PHONY: all clean

TARGET1 = ppcbc
TARGET2 = ppcbs

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(TARGET1).o err.o common.o 
	$(CC) $(LFLAGS) -o $@ $^
$(TARGET2): $(TARGET2).o err.o common.o
	$(CC) $(LFLAGS) -o $@ $^
# To są zależności wygenerowane automatycznie za pomocą polecenia `gcc -MM *.c`.

common.o: common.c err.h common.h
err.o: err.c err.h
ppcbc.o: ppcbc.c err.h common.h protocol.h protconst.h
ppcbs.o: ppcbs.c err.h common.h protocol.h protconst.h

clean:
	rm -f $(TARGET1) $(TARGET2) *.o *~
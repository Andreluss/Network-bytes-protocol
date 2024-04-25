CC     = g++
CFLAGS = -Wall -Wextra -O2 -std=gnu++17
LFLAGS =

# Define the object files directory
OBJDIR := obj

.PHONY: all clean

TARGET1 = ppcbc
TARGET2 = ppcbs

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(addprefix $(OBJDIR)/, $(TARGET1).o common.o protocol.o Client.o ClientUDP.o ClientUDPR.o ClientTCP.o)
	$(CC) $(LFLAGS) -o $@ $^
$(TARGET2): $(addprefix $(OBJDIR)/, $(TARGET2).o common.o protocol.o ServerUDP.o Server.o)
	$(CC) $(LFLAGS) -o $@ $^

# To są zależności wygenerowane automatycznie za pomocą polecenia `g++ -MM *.cpp`.
$(OBJDIR)/Client.o: Client.cpp Client.h protocol.h protconst.h common.h
$(OBJDIR)/ClientUDP.o: ClientUDP.cpp ClientUDP.h Client.h protocol.h protconst.h common.h
$(OBJDIR)/ClientUDPR.o: ClientUDPR.cpp ClientUDPR.h ClientUDP.h Client.h protocol.h protconst.h common.h
$(OBJDIR)/ClientTCP.o: ClientTCP.cpp ClientTCP.h Client.h protocol.h protconst.h common.h
$(OBJDIR)/Server.o: Server.cpp Server.h protocol.h protconst.h common.h
$(OBJDIR)/ServerUDP.o: ServerUDP.cpp ServerUDP.h Server.h protocol.h protconst.h common.h
$(OBJDIR)/common.o: common.cpp common.h
$(OBJDIR)/ppcbc.o: ppcbc.cpp common.h protocol.h protconst.h ClientUDP.h Client.h ClientUDPR.h
$(OBJDIR)/ppcbs.o: ppcbs.cpp common.h protocol.h protconst.h ServerUDP.h Server.h
$(OBJDIR)/protocol.o: protocol.cpp protocol.h protconst.h common.h

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET1) $(TARGET2)
	rm -rf $(OBJDIR)

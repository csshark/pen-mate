CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

SOURCES = packet_sniffer.c
EXECUTABLE = packet_sniffer
OBJECTS = $(SOURCES:.c=.o)

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean

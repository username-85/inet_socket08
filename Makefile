CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic -g -O0

.PHONY: default all clean

TARGET = sniffer
LDFLAGS = -lncurses
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

default: $(TARGET)
all: default

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(LDFLAGS) $(OBJECTS)

clean:
	-rm -f *.o
	-rm -f $(TARGET)

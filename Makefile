CC = g++
CFLAGS = -std=c++11 -Wall
SOURCE = main.cpp
OUTPUT = spectre

all: $(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) -o $(OUTPUT)

clean: 
	rm -rf $(OUTPUT)	
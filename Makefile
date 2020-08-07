CC=gcc
FLAGS=-ansi -Wall
TARGET_LIB=libsecuredns.a

SOURCE:= $(wildcard src/*.c)
OBJECTS:= $(patsubst %.c,%.o,$(SOURCE))


all: $(TARGET_LIB)

clean:
	rm -f $(TARGET_LIB)
	rm -f $(OBJECTS)


$(TARGET_LIB): $(OBJECTS) 
	ar rcs $@ $^

%:: %.c
	$(CC) $(FLAGS) $< -o $@

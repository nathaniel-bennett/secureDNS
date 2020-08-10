CC=gcc
FLAGS= -std=gnu89 -Wall
TARGET_LIB=libsecuredns.a
TEST_LIBS=-lssl -lcrypto

SOURCE:= $(wildcard src/*.c)
OBJECTS:= $(patsubst %.c,%.o,$(SOURCE))

TEST_SOURCE:= $(wildcard tests/*.c)
TESTS:= $(patsubst %.c,%,$(TEST_SOURCE))

all: $(TARGET_LIB)

test: $(TESTS)
	$(foreach VAR,$(TESTS), valgrind --leak-check=full $(VAR); printf "\n\n"; )

clean:
	rm -f $(TARGET_LIB)
	rm -f $(OBJECTS)
	rm -f $(TESTS)


$(TARGET_LIB): $(OBJECTS)
	ar rcs $@ $^

%.o:: %.c
	$(CC) -c $(FLAGS) $^ -o $@

tests/%:: tests/%.c $(TARGET_LIB)
	$(CC) $(FLAGS) $^ $(TEST_LIBS) -o $@

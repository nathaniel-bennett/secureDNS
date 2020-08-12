CC=gcc
FLAGS= -std=gnu89 -Wall
TARGET=libsecuredns.a
TEST_LIBS=-lssl -lcrypto
UID=$(shell id -u)

SOURCE:= $(wildcard src/*.c)
OBJECTS:= $(patsubst %.c,%.o,$(SOURCE))
INCLUDES:= $(wildcard include/*.h)

TEST_SOURCE:= $(wildcard tests/*.c)
TESTS:= $(patsubst %.c,%,$(TEST_SOURCE))

#PREFIX is environment variable, but if it is not set, then set default value
ifeq ($(PREFIX),)
    PREFIX:= /usr
endif

all: $(TARGET)


test: $(TESTS)
	$(foreach VAR,$(TESTS), valgrind --leak-check=full $(VAR); printf "\n\n"; )


install: $(TARGET)
	@if [ $(UID) -ne 0 ]; then \
		echo "Please run as root (sudo make install)"; \
		exit 1; \
	fi;

	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(TARGET) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
	install -m 644 $(INCLUDES) $(DESTDIR)$(PREFIX)/include/

uninstall:
	@if [ $(UID) -ne 0 ]; then \
		echo "Please run as root (sudo make install)"; \
		exit 1; \
	fi;

	rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET)
	rm -f $(patsubst %,$(DESTDIR)$(PREFIX)/%,$(INCLUDES))




clean:
	rm -f $(TARGET)
	rm -f $(OBJECTS)
	rm -f $(TESTS)


$(TARGET): $(OBJECTS)
	ar rcs $@ $^

%.o:: %.c
	$(CC) -c $(FLAGS) $^ -o $@

tests/%:: tests/%.c $(TARGET)
	$(CC) $(FLAGS) $^ $(TEST_LIBS) -o $@

CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lz -ldl -lm
UPX_VERSION ?= 5.1.1
UPX_DIR ?= tools/upx

TARGET := binsight
SRC := src/binsight.c
SRC += src/digests.c
SRC += src/native_headers.c
SRC += src/upx_repair.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean upx-tools

all: $(TARGET)

upx-tools:
	BINSIGHT_UPX_DIR="$(UPX_DIR)" tools/fetch-upx.sh "$(UPX_VERSION)"

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)

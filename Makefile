DEBUG ?= 0
# Compiler and flags
CC := gcc
CFLAGS := $(CFLAGS) -g  -W -Wall -Wno-unused-parameter -iquote include -iquote include/driver
ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif

# Directories
SRC_DIR := src
DRIVER_DIR := src/driver
TEST_DIR := test
BUILD_DIR := build


# Source and Object files
SRCS := $(wildcard $(SRC_DIR)/*.c) \
	$(wildcard $(DRIVER_DIR)/*.c) \
	$(wildcard $(TEST_DIR)/*.c)

OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET := test01

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ 

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $^ -o $@

clean: 
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean

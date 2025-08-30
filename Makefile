DEBUG ?= 0
# Compiler and flags
CC := gcc
CFLAGS := $(CFLAGS) -g  -W -Wall -Wno-unused-parameter -iquote include -iquote include/driver -iquote test
ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif

# Directories
SRC_DIR := src
DRIVER_DIR := src/driver
BUILD_DIR := build
BIN_DIR := bin
APP_DIR := app

# Source and Object files
SRCS := $(wildcard $(SRC_DIR)/*.c) \
	$(wildcard $(DRIVER_DIR)/*.c)
APP_SRCS := $(wildcard $(APP_DIR)/*.c)

OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRCS))
APP_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(APP_SRCS))


APPS := $(patsubst $(APP_DIR)/%.c,%,$(APP_SRCS))
BINS := $(patsubst %,$(BIN_DIR)/%,$(APPS))

.PHONY: all apps clean

all: apps

apps: $(BINS)

$(BIN_DIR)/%: $(OBJS) $(BUILD_DIR)/$(APP_DIR)/%.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $^ -o $@

clean: 
	rm -rf $(BUILD_DIR) $(BIN_DIR)

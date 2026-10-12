CXX ?= g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Werror -O2 -ffile-prefix-map=$(CURDIR)=.
INCLUDES := -Iinclude

SRC_DIR := src
TEST_DIR := tests
BUILD_DIR := build
BIN_DIR := bin

SRCS := $(SRC_DIR)/md5.cpp \
        $(SRC_DIR)/pcap_reader.cpp \
        $(SRC_DIR)/tls_ja3.cpp \
        $(SRC_DIR)/dns_analyzer.cpp \
        $(SRC_DIR)/arp_tracker.cpp

LIB_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))
MAIN_OBJ := $(BUILD_DIR)/main.o
TEST_OBJ := $(BUILD_DIR)/test_netpulse.o

TARGET := $(BIN_DIR)/netpulse
TEST_TARGET := $(BIN_DIR)/test_netpulse

.PHONY: all test clean fixtures

all: $(TARGET)

$(TARGET): $(LIB_OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(TEST_TARGET): $(LIB_OBJS) $(TEST_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/test_netpulse.o: $(TEST_DIR)/test_netpulse.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test: $(TEST_TARGET) fixtures
	./$(TEST_TARGET)

fixtures:
	@if [ ! -f fixtures/synthetic_capture.pcap ]; then \
		python3 fixtures/generate_fixtures.py; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) fixtures/synthetic_capture.pcap

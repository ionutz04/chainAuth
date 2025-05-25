# Makefile for IoT devices with auto-dependency installation

CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -ljsoncpp -lssl -lcrypto -lpthread
INCLUDES = -I./include -I/usr/include/jsoncpp  # Added JSONCPP system path
EXECUTABLES = IoTDevice2

.PHONY: all clean deps

all: deps $(EXECUTABLES)

# Dependency installation target
deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libjsoncpp-dev libssl-dev wget
	mkdir -p include
	if [ ! -f "./include/httplib.h" ]; then \
		wget -O ./include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h; \
	fi

IoTDevice2: main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBS)


clean:
	rm -f $(EXECUTABLES)

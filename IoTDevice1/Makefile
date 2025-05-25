# Makefile for IoT devices with cppcodec support
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -ljsoncpp -lssl -lcrypto -lpthread
INCLUDES = -I./include -I/usr/include/jsoncpp
EXECUTABLES = IoTDevice1

.PHONY: all clean deps

all: deps $(EXECUTABLES)

deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libjsoncpp-dev libssl-dev wget
	mkdir -p include
	
	# Download httplib if missing
	if [ ! -f "./include/httplib.h" ]; then \
		wget -O ./include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h; \
	fi
	
	# Clone cppcodec if missing
	if [ ! -d "./include/cppcodec" ]; then \
		git clone https://github.com/tplgy/cppcodec.git tmp_cppcodec && \
		mv tmp_cppcodec/include/cppcodec include/ && \
		rm -rf tmp_cppcodec; \
	fi

IoTDevice1: main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

clean:
	rm -f $(EXECUTABLES)

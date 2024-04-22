CXX?=/usr/bin/g++
LIBS?=-luring
CXXFLAGS?=$(LIBS) -std=gnu++2c -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-missing-field-initializers -fconcepts-diagnostics-depth=2 -ggdb
SRC=$(wildcard *.cpp)
HDR=$(wildcard *.h)
OBJ=$(addprefix build/, $(SRC:.cpp=.o))

build/main: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

build/%.o: %.cpp $(HDR) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build

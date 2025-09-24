
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17

# Targets
all: scanner puzzle

scanner: scanner.cpp
	$(CXX) $(CXXFLAGS) -o scanner scanner.cpp

puzzle: puzzlesolver.cpp
	$(CXX) $(CXXFLAGS) -o puzzle puzzlesolver.cpp

clean:
	rm -f scanner puzzle


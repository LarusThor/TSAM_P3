all: scanner puzzlesolver

scanner: scanner.cpp
	g++-15 -std=c++11 scanner.cpp -o $@

puzzlesolver: puzzlesolver.cpp
	g++-15 -std=c++11 puzzlesolver.cpp -o $@

clean:
	rm -f scanner puzzlesolver

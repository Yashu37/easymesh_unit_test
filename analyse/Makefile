CXX = g++

SRC = main.cpp bsta.cpp bsta_test.cpp
OUT = main

all: run wireshark

$(OUT): $(SRC)
	$(CXX) $(SRC) -o $(OUT) -fsanitize=address -g -O0 -Wall

run: $(OUT)
	./$(OUT)

wireshark:

clean:
	rm -f $(OUT) a.out

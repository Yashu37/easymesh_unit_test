CXX = g++

SRC = handle_channel_scan_request.cpp

#SRC = handle_ap_metrics_response.cpp handle_ap_metrics_response_test.cpp
OUT = main

all: run wireshark

$(OUT): $(SRC)

	$(CXX) $(SRC) -o $(OUT) -fsanitize=address -g -O0 -Wall

run: $(OUT)

	./$(OUT)

wireshark:

clean:

	rm -f $(OUT) a.out


CXX = g++

SRC = main.cpp bsta_test.cpp bsta.cpp common_test.cpp construct_test.cpp get_first_tlv_test.cpp get_first_tlv.cpp get_next_tlv_test.cpp get_next_tlv.cpp
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

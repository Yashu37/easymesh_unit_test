CXX = g++

SRC = main.cpp handle_topology_response.cpp handle_channel_scan_req.cpp handle_channel_scan_req_test.cpp  supported_service.cpp supported_service_test.cpp construct_supported_service.cpp handle_ap_operational_bss.cpp construct_ap_operational_bss.cpp ap_operational_bss_test.cpp handle_unassoc_sta_link_metrics_tlv.cpp construct_unassoc_sta_link_metrics_tlv.cpp construct_handle_channel_scan_req_test.cpp bsta_test.cpp bsta.cpp common_test.cpp construct_test.cpp get_first_tlv_test.cpp get_first_tlv.cpp get_next_tlv_test.cpp get_next_tlv.cpp handle_ap_metrics_response.cpp em_mes.cpp process.cpp bsta_gft_gnt_construct.cpp construct_ap_metrics_test.cpp handle_channel_scan_rprt.cpp   
#SRC = handle_ap_metrics_response.cpp handle_ap_metrics_response_test.cpp
OUT = main

all: run wireshark

$(OUT): $(SRC)

	$(CXX) $(SRC) -o $(OUT) -fsanitize=address -g -O0 -Wall

run: $(OUT)

	./$(OUT)

wireshark:

# Upstream gtest file, built with the stand-in headers in gtest_shim/
# Needs gtest once: sudo apt install libgtest-dev
GTEST_SRC = test_l1_em_configuration.cpp $(filter-out main.cpp,$(SRC))
GTEST_OUT = gtest_main

gtest: $(GTEST_SRC)

	$(CXX) -Igtest_shim $(GTEST_SRC) -o $(GTEST_OUT) -fsanitize=address -g -O0 -Wall -lgtest -lgtest_main -pthread
	./$(GTEST_OUT)

clean:

	rm -f $(OUT) $(GTEST_OUT) a.out

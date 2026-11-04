CXX = g++

SRC = main.cpp dpp_dummy.cpp construct_dpp_dummy.cpp dpp_dummy_test.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_test.cpp hal_ipc_server_set_neighbor_ap2_callback.cpp construct_hal_ipc_server_set_neighbor_ap2_callback.cpp hal_ipc_server_set_neighbor_ap2_callback_test.cpp hal_ipc_server_set_radio_channel_stats_callback.cpp construct_hal_ipc_server_set_radio_channel_stats_callback.cpp hal_ipc_server_set_radio_channel_stats_callback_test.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback_test.cpp
OUT = main

all: run

CXXFLAGS = -g -O0 -Wall -fpermissive -fsanitize=address
LDLIBS   = -ljansson -lpthread
OBJ = $(SRC:.cpp=.o)

# Incremental build: each .cpp -> .o (recompiled only when it or common.h changes)
%.o: %.cpp common.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	$(CXX) $(OBJ) -o $(OUT) -fsanitize=address $(LDLIBS)

run: $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT) *.o a.out

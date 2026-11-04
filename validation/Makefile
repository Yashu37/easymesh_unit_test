CXX = g++

SRC = main.cpp dpp_dummy.cpp construct_dpp_dummy.cpp dpp_dummy_test.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_test.cpp hal_ipc_server_set_neighbor_ap2_callback.cpp construct_hal_ipc_server_set_neighbor_ap2_callback.cpp hal_ipc_server_set_neighbor_ap2_callback_test.cpp hal_ipc_server_set_radio_channel_stats_callback.cpp construct_hal_ipc_server_set_radio_channel_stats_callback.cpp hal_ipc_server_set_radio_channel_stats_callback_test.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback_test.cpp hal_ipc_server_get_neighbor_ap2_callback.cpp construct_hal_ipc_server_get_neighbor_ap2_callback.cpp hal_ipc_server_get_neighbor_ap2_callback_test.cpp hal_ipc_server_get_radio_channel_stats_callback.cpp construct_hal_ipc_server_get_radio_channel_stats_callback.cpp hal_ipc_server_get_radio_channel_stats_callback_test.cpp get_processor_desc.cpp construct_get_processor_desc.cpp get_processor_desc_test.cpp rdk_hal_ipc_exec.cpp construct_rdk_hal_ipc_exec.cpp rdk_hal_ipc_exec_test.cpp rdk_hal_server_func.cpp construct_rdk_hal_server_func.cpp rdk_hal_server_func_test.cpp rdk_create_hal_ipc_node.cpp construct_rdk_create_hal_ipc_node.cpp rdk_create_hal_ipc_node_test.cpp cleanup_client_data.cpp construct_cleanup_client_data.cpp cleanup_client_data_test.cpp cleanup_desc_scratch_buf.cpp construct_cleanup_desc_scratch_buf.cpp cleanup_desc_scratch_buf_test.cpp sync_hostapd_freq_param.cpp construct_sync_hostapd_freq_param.cpp sync_hostapd_freq_param_test.cpp ipc_server_output.c construct_ipc_server_output.cpp ipc_server_output_test.cpp
OUT = main

all: run

CXXFLAGS = -g -O0 -Wall -fpermissive -fsanitize=address
HALIF    = $(HOME)/Desktop/G/halinterface/include
LDLIBS   = -ljansson -lpthread
OBJ = $(patsubst %.c,%.o,$(SRC:.cpp=.o))

# Incremental build: each .cpp -> .o (recompiled only when it or common.h changes)
%.o: %.cpp common.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ipc_server_output: handler is compiled as C (the original is C), the harness TUs use the REAL wifi_hal.h
ipc_server_output.o: ipc_server_output.c hso_hal_ipc.h
	gcc -g -O0 -Wall -Wno-unused-variable -Wno-sign-compare -fsanitize=address -I. -I$(HALIF) -c $< -o $@
construct_ipc_server_output.o ipc_server_output_test.o: CXXFLAGS += -I. -I$(HALIF)
construct_ipc_server_output.o: hso_hal_ipc.h
ipc_server_output_test.o: hso_hal_ipc.h

$(OUT): $(OBJ)
	$(CXX) $(OBJ) -o $(OUT) -fsanitize=address $(LDLIBS)

run: $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT) *.o a.out

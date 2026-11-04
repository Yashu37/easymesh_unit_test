CXX = g++

SRC = main.cpp dpp_dummy.cpp construct_dpp_dummy.cpp dpp_dummy_test.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_test.cpp hal_ipc_server_set_neighbor_ap2_callback.cpp construct_hal_ipc_server_set_neighbor_ap2_callback.cpp hal_ipc_server_set_neighbor_ap2_callback_test.cpp hal_ipc_server_set_radio_channel_stats_callback.cpp construct_hal_ipc_server_set_radio_channel_stats_callback.cpp hal_ipc_server_set_radio_channel_stats_callback_test.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp construct_hal_ipc_server_get_ap_assoc_dev_diag_res3_callback.cpp hal_ipc_server_get_ap_assoc_dev_diag_res3_callback_test.cpp hal_ipc_server_get_neighbor_ap2_callback.cpp construct_hal_ipc_server_get_neighbor_ap2_callback.cpp hal_ipc_server_get_neighbor_ap2_callback_test.cpp hal_ipc_server_get_radio_channel_stats_callback.cpp construct_hal_ipc_server_get_radio_channel_stats_callback.cpp hal_ipc_server_get_radio_channel_stats_callback_test.cpp get_processor_desc.cpp construct_get_processor_desc.cpp get_processor_desc_test.cpp rdk_hal_ipc_exec.cpp construct_rdk_hal_ipc_exec.cpp rdk_hal_ipc_exec_test.cpp rdk_hal_server_func.cpp construct_rdk_hal_server_func.cpp rdk_hal_server_func_test.cpp rdk_create_hal_ipc_node.cpp construct_rdk_create_hal_ipc_node.cpp rdk_create_hal_ipc_node_test.cpp cleanup_client_data.cpp construct_cleanup_client_data.cpp cleanup_client_data_test.cpp cleanup_desc_scratch_buf.cpp construct_cleanup_desc_scratch_buf.cpp cleanup_desc_scratch_buf_test.cpp sync_hostapd_freq_param.cpp construct_sync_hostapd_freq_param.cpp sync_hostapd_freq_param_test.cpp ipc_server_output.c construct_ipc_server_output.cpp ipc_server_output_test.cpp ipc_client_notification_input.c construct_ipc_client_notification_input.cpp ipc_client_notification_input_test.cpp hwr_common.cpp wifi_hal_setRadioStatsEnable.cpp construct_wifi_hal_setRadioStatsEnable.cpp wifi_hal_setRadioStatsEnable_test.cpp wifi_hal_getSSIDNumberOfEntries.cpp construct_wifi_hal_getSSIDNumberOfEntries.cpp wifi_hal_getSSIDNumberOfEntries_test.cpp wifi_hal_getApAssociatedDeviceStats.cpp construct_wifi_hal_getApAssociatedDeviceStats.cpp wifi_hal_getApAssociatedDeviceStats_test.cpp wifi_hal_getRadioChannelStats.cpp construct_wifi_hal_getRadioChannelStats.cpp wifi_hal_getRadioChannelStats_test.cpp wifi_hal_getSSIDTrafficStats2.cpp construct_wifi_hal_getSSIDTrafficStats2.cpp wifi_hal_getSSIDTrafficStats2_test.cpp wifi_hal_getApAssociatedDeviceRxStatsResult.cpp construct_wifi_hal_getApAssociatedDeviceRxStatsResult.cpp wifi_hal_getApAssociatedDeviceRxStatsResult_test.cpp wifi_hal_getSSIDEnable.cpp construct_wifi_hal_getSSIDEnable.cpp wifi_hal_getSSIDEnable_test.cpp wifi_hal_getSSIDRadioIndex.cpp construct_wifi_hal_getSSIDRadioIndex.cpp wifi_hal_getSSIDRadioIndex_test.cpp
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

ipc_client_notification_input.o: ipc_client_notification_input.c hso_hal_ipc.h
	gcc -g -O0 -Wall -Wno-unused-variable -Wno-sign-compare -fsanitize=address -I. -I$(HALIF) -c $< -o $@
construct_ipc_client_notification_input.o ipc_client_notification_input_test.o: CXXFLAGS += -I. -I$(HALIF)
construct_ipc_client_notification_input.o ipc_client_notification_input_test.o: hso_hal_ipc.h hcn_defs.h

hwr_common.o wifi_hal_setRadioStatsEnable.o construct_wifi_hal_setRadioStatsEnable.o wifi_hal_setRadioStatsEnable_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_setRadioStatsEnable.o construct_wifi_hal_setRadioStatsEnable.o wifi_hal_setRadioStatsEnable_test.o: hso_hal_ipc.h hwr_defs.h hwr_setRadioStatsEnable.h

wifi_hal_getSSIDNumberOfEntries.o construct_wifi_hal_getSSIDNumberOfEntries.o wifi_hal_getSSIDNumberOfEntries_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getSSIDNumberOfEntries.o construct_wifi_hal_getSSIDNumberOfEntries.o wifi_hal_getSSIDNumberOfEntries_test.o: hso_hal_ipc.h hwr_defs.h hwr_ssid.h

wifi_hal_getApAssociatedDeviceStats.o construct_wifi_hal_getApAssociatedDeviceStats.o wifi_hal_getApAssociatedDeviceStats_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getApAssociatedDeviceStats.o construct_wifi_hal_getApAssociatedDeviceStats.o wifi_hal_getApAssociatedDeviceStats_test.o: hso_hal_ipc.h hwr_defs.h hwr_gas.h

wifi_hal_getRadioChannelStats.o construct_wifi_hal_getRadioChannelStats.o wifi_hal_getRadioChannelStats_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getRadioChannelStats.o construct_wifi_hal_getRadioChannelStats.o wifi_hal_getRadioChannelStats_test.o: hso_hal_ipc.h hwr_defs.h hwr_grc.h

wifi_hal_getSSIDTrafficStats2.o construct_wifi_hal_getSSIDTrafficStats2.o wifi_hal_getSSIDTrafficStats2_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getSSIDTrafficStats2.o construct_wifi_hal_getSSIDTrafficStats2.o wifi_hal_getSSIDTrafficStats2_test.o: hso_hal_ipc.h hwr_defs.h hwr_gts.h

wifi_hal_getApAssociatedDeviceRxStatsResult.o construct_wifi_hal_getApAssociatedDeviceRxStatsResult.o wifi_hal_getApAssociatedDeviceRxStatsResult_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getApAssociatedDeviceRxStatsResult.o construct_wifi_hal_getApAssociatedDeviceRxStatsResult.o wifi_hal_getApAssociatedDeviceRxStatsResult_test.o: hso_hal_ipc.h hwr_defs.h hwr_grx.h

wifi_hal_getSSIDEnable.o construct_wifi_hal_getSSIDEnable.o wifi_hal_getSSIDEnable_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getSSIDEnable.o construct_wifi_hal_getSSIDEnable.o wifi_hal_getSSIDEnable_test.o: hso_hal_ipc.h hwr_defs.h hwr_gse.h

wifi_hal_getSSIDRadioIndex.o construct_wifi_hal_getSSIDRadioIndex.o wifi_hal_getSSIDRadioIndex_test.o: CXXFLAGS += -I. -I$(HALIF)
wifi_hal_getSSIDRadioIndex.o construct_wifi_hal_getSSIDRadioIndex.o wifi_hal_getSSIDRadioIndex_test.o: hso_hal_ipc.h hwr_defs.h hwr_gsr.h

$(OUT): $(OBJ)
	$(CXX) $(OBJ) -o $(OUT) -fsanitize=address $(LDLIBS)

run: $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT) *.o a.out

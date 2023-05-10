target_sources(iotcore
        PRIVATE
        iot_bsp_debug_posix.c
        iot_bsp_fs_posix.c
        iot_bsp_nv_data_posix.c
        iot_bsp_random_posix.c
        iot_bsp_system_posix.c
        iot_bsp_wifi_posix.c
        )

target_link_libraries(iotcore PUBLIC pthread rt)

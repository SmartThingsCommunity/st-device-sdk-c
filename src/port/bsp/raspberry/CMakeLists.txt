include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GIO2 REQUIRED gio-2.0)

target_sources(iotcore
        PRIVATE
        iot_bsp_debug_linux.c
        iot_bsp_fs_linux.c
        iot_bsp_nv_data_linux.c
        iot_bsp_random_linux.c
        iot_bsp_system_linux.c
        iot_bsp_wifi_linux.c
		wifi_supplicant.c
        )

target_include_directories(iotcore PRIVATE . ${GLIB2_INCLUDE_DIRS} ${GIO2_INCLUDE_DIRS})

target_link_libraries(iotcore PUBLIC pthread rt ${GIO2_LIBRARIES} ${GLIB2_LIBRARIES})

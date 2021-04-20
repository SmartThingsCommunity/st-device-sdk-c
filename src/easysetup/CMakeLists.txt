if(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP)
    set(EASYSETUP_D2D_SOURCES
        "${EASYSETUP_D2D_SOURCES}"
        http/iot_easysetup_http_parser.c
        http/iot_easysetup_http.c
        http/easysetup_http.h
        )
endif()

if(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
    set(EASYSETUP_D2D_SOURCES
        "${EASYSETUP_D2D_SOURCES}"
        http/tls/iot_easysetup_d2d_tls.c
        http/tls/iot_easysetup_http_tls.c
    )
else()
    set(EASYSETUP_D2D_SOURCES
        "${EASYSETUP_D2D_SOURCES}"
        http/tcp/iot_easysetup_d2d_tcp.c
        http/tcp/iot_easysetup_httpd.c
    )
endif()

if(CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_SSID)
    set(EASYSETUP_DISCOVERY_SOURCES
        "${EASYSETUP_DISCOVERY_SOURCES}"
        discovery/iot_easysetup_discovery_ssid.c
        )
endif()

target_sources(iotcore
               PRIVATE
               iot_easysetup_st_mqtt.c
               ${EASYSETUP_D2D_SOURCES}
               ${EASYSETUP_DISCOVERY_SOURCES}
               )

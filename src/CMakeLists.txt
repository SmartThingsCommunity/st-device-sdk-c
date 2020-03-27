set(CJSON_DIR deps/json)
include(CheckIncludeFile)
check_include_file(${CJSON_DIR}/cJSON/cJSON.h CJSON_H)
if (NOT CJSON_H)
    message(STATUS "submodule init for cJSON")
    execute_process(COMMAND git submodule update --init ${CJSON_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT CJSON_H)

set(MBEDTLS_DIR deps/mbedtls)
check_include_file(${MBEDTLS_DIR}/mbedtls/include/ssl.h MBEDTLS_H)
if (NOT MBEDTLS_H)
    message(STATUS "submodule init for mbedtls")
    execute_process(COMMAND git submodule update --init ${MBEDTLS_DIR}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (NOT MBEDTLS_H)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fpic")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable building cJSON test" FORCE)
add_subdirectory(deps/json/cJSON)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
add_subdirectory(deps/mbedtls/mbedtls)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_BUILD_TYPE MATCHES Debug)
    foreach(mock ${MOCKED_FUNCTIONS})
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wl,--wrap=${mock}")
    endforeach()
endif()

set(BOILERPLATE_HEADER include/certs/boilerplate.h)
file(GLOB ROOT_CA_FILE_LIST "certs/root_ca_*.pem")
set(ROOT_CA_FILE certs/root_ca.pem)
set(ROOT_CA_SOURCE iot_root_ca.c)
add_custom_command(
        PRE_BUILD
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${ROOT_CA_SOURCE}
        COMMENT "Generating root certiciate"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND if [ -e ${ROOT_CA_FILE} ] \; then rm ${ROOT_CA_FILE} \; fi \;
        COMMAND cat ${ROOT_CA_FILE_LIST} >> ${ROOT_CA_FILE}
        COMMAND cat ${BOILERPLATE_HEADER} > ${ROOT_CA_SOURCE}
        COMMAND xxd -i ${ROOT_CA_FILE} >> ${ROOT_CA_SOURCE}
        COMMAND sed -i.bak 's/cert.*_pem/st_root_ca/g' ${ROOT_CA_SOURCE}
        COMMAND sed -i.bak 's/unsigned/const unsigned/g' ${ROOT_CA_SOURCE}
        COMMAND rm -f ${ROOT_CA_SOURCE}.bak
        COMMAND rm -f ${ROOT_CA_FILE}
        BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/${ROOT_CA_SOURCE}
)

add_library(iotcore
        iot_api.c
        iot_crypto.c
        iot_capability.c
        iot_wt.c
        iot_main.c
        iot_nv_data.c
        iot_util.c
        iot_uuid.c
        ${ROOT_CA_SOURCE}
        )

target_link_libraries(iotcore
        PRIVATE
        curl
        sodium
        mbedcrypto
        mbedx509
        mbedtls
        cjson
        )

target_include_directories(iotcore
        PRIVATE
        deps/json/cJSON
        deps/mbedtls/mbedtls/include
        port/net/mbedtls
        include/bsp
        include/bsp/posix
        include/os
        include/mqtt
        include/external
        PUBLIC
        include
        )

add_subdirectory(port/bsp/posix)
add_subdirectory(port/os/posix)
add_subdirectory(port/net)
add_subdirectory(easysetup)
add_subdirectory(mqtt)
add_subdirectory(crypto)

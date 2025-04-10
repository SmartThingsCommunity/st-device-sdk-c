cmake_minimum_required(VERSION 3.5)
project(example)

add_executable(example example.c)

add_custom_target(
		convertJson
		COMMENT "Converting jsons to objects"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND sh -c \"ld -r -b binary -o onboarding_config.o onboarding_config.json\"
        COMMAND sh -c \"ld -r -b binary -o device_info.o device_info.json\"
)

add_dependencies(example convertJson)

set(stdk_config ${CMAKE_CURRENT_LIST_DIR}/stdkconfig.cmake)
add_subdirectory(../.. iotcore)
target_link_libraries(example PUBLIC iotcore ${CMAKE_CURRENT_SOURCE_DIR}/onboarding_config.o ${CMAKE_CURRENT_SOURCE_DIR}/device_info.o)

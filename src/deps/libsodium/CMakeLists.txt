
file(GLOB_RECURSE libsodium_SRCS libsodium/src/*.c)
SET(LIBSODIUM_CFLAGS
        CONFIGURED
        NATIVE_LITTLE_ENDIAN
        HAVE_WEAK_SYMBOLS
        __STDC_LIMIT_MACROS
        __STDC_CONSTANT_MACROS
        )
foreach(libsodium_cflags ${LIBSODIUM_CFLAGS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${libsodium_cflags}")
endforeach()

add_library(sodium
        ${libsodium_SRCS}
        )
target_include_directories(sodium
        PRIVATE
        libsodium/src/libsodium/include
        libsodium/src/libsodium/include/sodium
        port/include/sodium
        port/include
        )
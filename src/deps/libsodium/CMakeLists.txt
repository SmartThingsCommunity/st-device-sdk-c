aux_source_directory(libsodium LIBSODIUM_SRC)
target_sources(iotcore
        PRIVATE
        ${LIBSODIUM_SRC}
        )
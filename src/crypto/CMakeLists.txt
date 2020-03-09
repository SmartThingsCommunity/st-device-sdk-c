target_sources(iotcore
        PRIVATE
        iot_crypto_ed25519.c
        mbedtls/iot_crypto_mbedtls.c
        ss/iot_crypto_ss.c
        )
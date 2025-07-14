## Common

#### CONFIG_STDK_IOT_CORE
- Type : Bool
- Description : Enable SmartThings Device SDK block

## Target Porting System

#### CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32
- Type : Bool
- Description : Choose esp32 board as target bsp board

#### CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32S2
- Type : Bool
- Description : Choose esp32s2 board as target bsp board

#### CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32C3
- Type : Bool
- Description : Choose esp32c3 board as target bsp board

#### CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS
- Type : Bool
- Description : Choose freertos as target os system

#### CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX
- Type : Bool
- Description : Choose posix compatible system as target os system

## Onboarding
#### CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP
- Type : Bool
- Description : STDK will use HTTP(softAP) method for onboarding.

#### CONFIG_STDK_IOT_CORE_EASYSETUP_BLE
- Type : Bool
- Description : STDK will use BLE method for onboarding.

#### CONFIG_STDK_IOT_CORE_EASYSETUP_DISCOVERY_ADVERTISER
- Type : Bool
- Description : STDK will use BLE advertisement for onboarding.

## Log Level
#### CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR
- Type : Bool
- Description : Print error level message log.

#### CONFIG_STDK_IOT_CORE_LOG_LEVEL_WARN
- Type : Bool
- Description : Print warn level message log.

#### CONFIG_STDK_IOT_CORE_LOG_LEVEL_INFO
- Type : Bool
- Description : Print info level message log.

#### CONFIG_STDK_IOT_CORE_LOG_LEVEL_DEBUG
- Type : Bool
- Description : Print debug level message log.

## Security
#### CONFIG_STDK_IOT_CORE_USE_MBEDTLS
- Type : Bool
- Description : STDK will use thin wrappers around mbedTLS for Crypto (sha, sign, ...) operations.

#### CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA
- Type : Bool
- Description : STDK support RSA device key type.

#### CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA
- Type : Bool
- Description : STDK support ECDSA device key type.

#### CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519
- Type : Bool
- Description : STDK support ED25519 device key type.

#### CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION
- Type : Bool
- Description : STDK load device key from stnv partition.

#### CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE
- Type : Bool
- Description : SW based security block like mbedtls is used for security operation.

#### CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE
- Type : Bool
- Description : HW based security block like SE is used for security operation.

## Feature
#### CONFIG_STDK_IOT_CORE_EASYSETUP_WIFI_UPDATE
- Type : Bool
- Description : Enable wifi update functionality.
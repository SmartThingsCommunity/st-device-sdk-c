/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef _IOT_NV_DATA_H_
#define _IOT_NV_DATA_H_

#include "iot_error.h"
#include "iot_main.h"
#include "security/iot_security_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name iot_nvd_t
 * @brief internal nv data codes.
 */
typedef enum {
	IOT_NVD_UNKNOWN = 0,

	/* wifi prov data */
	IOT_NVD_WIFI_PROV_STATUS,
	IOT_NVD_AP_SSID,
	IOT_NVD_AP_PASS,
	IOT_NVD_AP_BSSID,
	IOT_NVD_AP_AUTH_TYPE,
	/* wifi prov data */

	/* cloud prov data */
	IOT_NVD_CLOUD_PROV_STATUS,
	IOT_NVD_SERVER_URL,
	IOT_NVD_SERVER_PORT,
	IOT_NVD_LOCATION_ID,
	IOT_NVD_ROOM_ID,
	IOT_NVD_LABEL,
	/* cloud prov data */

	IOT_NVD_DEVICE_ID,
	IOT_NVD_MISC_INFO,

	/* stored in stnv partition (manufacturer data) */
	IOT_NVD_FACTORY,
	IOT_NVD_PRIVATE_KEY = IOT_NVD_FACTORY,
	IOT_NVD_PUBLIC_KEY,
	IOT_NVD_ROOT_CA_CERT,
	IOT_NVD_SUB_CA_CERT,
	IOT_NVD_DEVICE_CERT,
	IOT_NVD_SERIAL_NUM,
	/* stored in stnv partition (manufacturer data) */

	IOT_NVD_MAX
} iot_nvd_t;

/*
 * Memory Management
 *
 * Get API returns heap memory allocated pointer (malloc).
 * The caller is always responsible to free the allocated pointer after using the data.
 *
 */

/**
 * @brief Initialize a nv file-system.
 *
 * @details This function initializes the nv file-system of the device.
 * You must call this function before using nv management function.
 * @retval IOT_ERROR_NONE NV file-system init successful.
 * @retval IOT_ERROR_INIT_FAIL NV file-system init failed.
 *
 * @see iot_bsp_fs_init
 */
iot_error_t iot_nv_init(unsigned char *device_info, size_t device_info_len);

/**
 * @brief Deinitialize a nv file-system.
 *
 * @retval IOT_ERROR_NONE NV file-system deinit successful.
 * @retval IOT_ERROR_DEINIT_FAIL NV file-system deinit failed.
 *
 * @see iot_bsp_fs_deinit
 */
iot_error_t iot_nv_deinit();

/**
 * @brief Get provisioning data from the nv file-system.
 *
 * @param[out] prov_data A pointer to data structure to store the provisioning data from the nv file-system.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 *
 * @see iot_nv_get_wifi_prov_data
 * @see iot_nv_get_cloud_prov_data
 */
iot_error_t iot_nv_get_prov_data(struct iot_device_prov_data* prov_data);

/**
 * @brief Set provisioning data to the nv file-system.
 *
 * @param[in] prov_data A pointer to provisioning data structure.
 * @retval IOT_ERROR_NONE Set nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Set nv data failed.
 *
 * @see iot_nv_set_wifi_prov_data
 * @see iot_nv_set_cloud_prov_data
 */
iot_error_t iot_nv_set_prov_data(struct iot_device_prov_data* prov_data);

/**
 * @brief Erase wifi/cloud provisioning data.
 *
 * @details This function erases the wifi/cloud provisioning data in File-system.
 * @retval IOT_ERROR_NONE NV data erase successful.
 * @retval IOT_ERROR_NV_DATA_ERROR NV data erase failed.
 */
iot_error_t iot_nv_erase_prov_data();

/**
 * @brief Get wifi provisioning data from the nv file-system.
 *
 * @param[out] wifi_prov A pointer to data structure to store the wifi provisioning data from the nv file-system.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_wifi_prov_data(struct iot_wifi_prov_data* wifi_prov);

/**
 * @brief Set wifi provisioning data to the nv file-system.
 *
 * @param[in] wifi_prov A pointer to wifi provisioning data structure.
 * @retval IOT_ERROR_NONE Set nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Set nv data failed.
 */
iot_error_t iot_nv_set_wifi_prov_data(struct iot_wifi_prov_data* wifi_prov);

/**
 * @brief Get cloud provisioning data from the nv file-system.
 *
 * @param[out] cloud_prov A pointer to data structure to store the cloud provisioning data from the nv file-system.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_cloud_prov_data(struct iot_cloud_prov_data* cloud_prov);

/**
 * @brief Set cloud provisioning data to the nv file-system.
 *
 * @param[in] cloud_prov A pointer to cloud provisioning data structure.
 * @retval IOT_ERROR_NONE Set nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Set nv data failed.
 */
iot_error_t iot_nv_set_cloud_prov_data(struct iot_cloud_prov_data* cloud_prov);

/**
 * @brief Get a private key from the nv file-system.
 *
 * @param[out] key A pointer to data array to store the private key from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_private_key(char** key, size_t* len);

/**
 * @brief Get a public key from the nv file-system.
 *
 * @param[out] key A pointer to data array to store the public key from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_public_key(char** key, size_t* len);

/**
 * @brief Get a root cert from the nv file-system.
 *
 * @param[out] cert A pointer to data array to store the root cert from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_root_certificate(char** cert, size_t* len);

/**
 * @brief Get a client cert from the nv file-system.
 *
 * @param[out] cert A pointer to data array to store the client cert from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_client_certificate(char** cert, size_t* len);

/**
 * @brief Get a device id from the nv file-system.
 *
 * @param[out] device_id A pointer to data array to store the device id from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_device_id(char** device_id, size_t* len);

/**
 * @brief Set a device id to the nv file-system.
 *
 * @param[in] device_id The string of device id from MQTT Server.
 * @retval IOT_ERROR_NONE Set nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Set nv data failed.
 */
iot_error_t iot_nv_set_device_id(const char* device_id);

/**
 * @brief Get a miscellaneous info from the nv file-system.
 *
 * @param[out] misc_info A pointer to data array to store the miscellaneous info from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_misc_info(char** misc_info, size_t* len);

/**
 * @brief Set a miscellaneous info to the nv file-system.
 *
 * @param[in] misc_info The string of miscellaneous info from iot-core.
 * @retval IOT_ERROR_NONE Set nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Set nv data failed.
 */
iot_error_t iot_nv_set_misc_info(const char* misc_info);

/**
 * @brief Get a serial number from the nv file-system.
 *
 * @param[out] sn A pointer to data array to store the serial number from the nv file-system.
 * @param[out] len The length of the nv data.
 * @retval IOT_ERROR_NONE Get nv data successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid argument.
 * @retval IOT_ERROR_NV_DATA_ERROR Get nv data failed.
 *
 * @warning The caller is always responsible to free the allocated pointer after using the data.
 */
iot_error_t iot_nv_get_serial_number(char** sn, size_t* len);

/**
 * @brief Erase a nv data.
 *
 * @details This function erase the nv data completely in File-system.
 * @param[in] nv_type The type of nv data to erase.
 * @retval IOT_ERROR_NONE NV data erase successful.
 * @retval IOT_ERROR_INVALID_ARGS Invalid nv type.
 * @retval IOT_ERROR_NV_DATA_ERROR NV data erase failed.
 * @retval IOT_ERROR_NV_DATA_NOT_EXIST NV data does not exist.
 */
iot_error_t iot_nv_erase(iot_nvd_t nv_type);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
/**
 * @brief Get nv data from device info
 *
 * @param[in] nv_id The type of nv data
 * @param[out] output_buf a pointer to the security buffer of data
 * @retval IOT_ERROR_NONE success
 * @retval IOT_ERROR_INVALID_ARGS input parameter is invalid
 * @retval IOT_ERROR_MEM_ALLOC memory allocation for data is failed
 * @retval IOT_ERROR_UNINITIALIZED device info does not initialized
 * @retval IOT_ERROR_NV_DATA_ERROR nv_id is invalid to get data from device info
 */
iot_error_t iot_nv_get_data_from_device_info(iot_nvd_t nv_id, iot_security_buffer_t *output_buf);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _IOT_NV_DATA_H_ */

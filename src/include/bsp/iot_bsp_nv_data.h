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

#ifndef _IOT_BSP_NV_DATA_H_
#define _IOT_BSP_NV_DATA_H_

#include "iot_nv_data.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get a nv data path.
 *
 * @details This function will return the nv data path.
 * The detail of data path depends on the file-system type.
 * ex : espressif nvs-system - nvs key ("nvItemKey")
 *      linux file-system - file path ("/stnv/nvItemKey")
 *
 * @param[in] nv_type The type of nv data. declaration is in "iot_nv_data.h"
 * @return nv data path.
 *
 * @see iot_nv_data.h
 */
const char* iot_bsp_nv_get_data_path(iot_nvd_t nv_type);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_BSP_NV_DATA_H_ */

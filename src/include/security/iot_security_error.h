/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_SECURITY_ERROR_H_
#define _IOT_SECURITY_ERROR_H_

#define IOT_ERROR_SECURITY_INIT                 (IOT_ERROR_SECURITY_BASE - 1)
#define IOT_ERROR_SECURITY_DEINIT               (IOT_ERROR_SECURITY_BASE - 2)
#define IOT_ERROR_SECURITY_CONTEXT_NULL         (IOT_ERROR_SECURITY_BASE - 3)
#define IOT_ERROR_SECURITY_BE_CONTEXT_NULL      (IOT_ERROR_SECURITY_BASE - 4)
#define IOT_ERROR_SECURITY_BE_FUNC_NULL         (IOT_ERROR_SECURITY_BASE - 5)
#define IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL  (IOT_ERROR_SECURITY_BASE - 6)
#define IOT_ERROR_SECURITY_STORAGE_INIT         (IOT_ERROR_SECURITY_BASE - 120)
#define IOT_ERROR_SECURITY_STORAGE_DEINIT       (IOT_ERROR_SECURITY_BASE - 121)
#define IOT_ERROR_SECURITY_STORAGE_READ         (IOT_ERROR_SECURITY_BASE - 122)
#define IOT_ERROR_SECURITY_STORAGE_WRITE        (IOT_ERROR_SECURITY_BASE - 123)
#define IOT_ERROR_SECURITY_STORAGE_REMOVE       (IOT_ERROR_SECURITY_BASE - 124)
#define IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL  (IOT_ERROR_SECURITY_BASE - 125)
#define IOT_ERROR_SECURITY_STORAGE_INVALID_ID   (IOT_ERROR_SECURITY_BASE - 126)
#define IOT_ERROR_SECURITY_FS_OPEN              (IOT_ERROR_SECURITY_BASE - 200)
#define IOT_ERROR_SECURITY_FS_READ              (IOT_ERROR_SECURITY_BASE - 201)
#define IOT_ERROR_SECURITY_FS_WRITE             (IOT_ERROR_SECURITY_BASE - 202)
#define IOT_ERROR_SECURITY_FS_CLOSE             (IOT_ERROR_SECURITY_BASE - 203)
#define IOT_ERROR_SECURITY_FS_REMOVE            (IOT_ERROR_SECURITY_BASE - 204)
#define IOT_ERROR_SECURITY_FS_BUFFER            (IOT_ERROR_SECURITY_BASE - 205)
#define IOT_ERROR_SECURITY_FS_NOT_FOUND         (IOT_ERROR_SECURITY_BASE - 208)
#define IOT_ERROR_SECURITY_FS_INVALID_ARGS      (IOT_ERROR_SECURITY_BASE - 209)
#define IOT_ERROR_SECURITY_FS_INVALID_TARGET    (IOT_ERROR_SECURITY_BASE - 210)
#define IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET    (IOT_ERROR_SECURITY_BASE - 211)
#define IOT_ERROR_SECURITY_BSP_FN_LOAD_NULL     (IOT_ERROR_SECURITY_BASE - 220)
#define IOT_ERROR_SECURITY_BSP_FN_STORE_NULL    (IOT_ERROR_SECURITY_BASE - 221)
#define IOT_ERROR_SECURITY_BSP_FN_REMOVE_NULL   (IOT_ERROR_SECURITY_BASE - 222)

#endif /* _IOT_SECURITY_ERROR_H_ */

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
#include <hosal_rng.h>
#include <stdint.h>
#include "iot_bsp_random.h"
#include "iot_debug.h"
#include "iot_error.h"

unsigned int iot_bsp_random()
{
	int ret = -1;
	unsigned int random;
	/*init rng */
	hosal_rng_init();
	ret = hosal_random_num_read(&random, sizeof(random)/sizeof(uint32_t));
	if (0 != ret) {
        IOT_ERROR("rng read error\r\n");
		return IOT_ERROR_INVALID_ARGS;
    }

	return random;
}

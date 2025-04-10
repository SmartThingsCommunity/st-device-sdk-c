/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "iot_bsp_random.h"

unsigned int iot_bsp_random(void)
{
	static int seed = 0;

	if (seed == 0) {
		srand(time(NULL));
		seed = 1;
	}

	uint32_t rand1 = rand() << 24;
	uint32_t rand2 = (rand() << 16) & 0x00FF0000;
	uint32_t rand3 = (rand() << 8) & 0x0000FF00;;
	uint32_t rand4 = rand() & 0x000000FF;

	return (rand1 | rand2 | rand3 | rand4) % UINT32_MAX;
}

/* ***************************************************************************
 *
 * Copyright 2019-2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_GRID_STATE_
#define _IOT_CAPS_HELPER_GRID_STATE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_GRIDSTATE_GRID_VALUE_ONGRID, CAP_ENUM_GRIDSTATE_GRID_VALUE_OFFGRID, CAP_ENUM_GRIDSTATE_GRID_VALUE_MAX };

const static struct iot_caps_gridState {
    const char *id;
    const struct gridState_attr_grid {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_GRIDSTATE_GRID_VALUE_MAX];
        const char *value_OnGrid;
        const char *value_OffGrid;
    } attr_grid;
} caps_helper_gridState = {
    .id = "gridState",
    .attr_grid =
        {
            .name = "grid",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"OnGrid", "OffGrid"},
            .value_OnGrid = "OnGrid",
            .value_OffGrid = "OffGrid",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_GRID_STATE_ */

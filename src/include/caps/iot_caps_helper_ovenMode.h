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

#ifndef _IOT_CAPS_HELPER_OVEN_MODE_
#define _IOT_CAPS_HELPER_OVEN_MODE_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_OVENMODE_SUPPORTEDOVENMODES_VALUE_MAX 29
enum {
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_HEATING,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_GRILL,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_WARMING,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_DEFROSTING,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_CONVENTIONAL,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_BAKE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_BOTTOMHEAT,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_CONVECTIONBAKE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_CONVECTIONROAST,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_BROIL,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_CONVECTIONBROIL,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_STEAMCOOK,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_STEAMBAKE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_STEAMROAST,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_STEAMBOTTOMHEATPLUSCONVECTION,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MICROWAVE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MWPLUSGRILL,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MWPLUSCONVECTION,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MWPLUSHOTBLAST,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MWPLUSHOTBLAST2,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_SLIMMIDDLE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_SLIMSTRONG,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_SLOWCOOK,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_PROOF,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_DEHYDRATE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_OTHERS,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_STRONGSTEAM,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_DESCALE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_RINSE,
    CAP_ENUM_OVENMODE_OVENMODE_VALUE_MAX
};

const static struct iot_caps_ovenMode {
    const char *id;
    const struct ovenMode_attr_supportedOvenModes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OVENMODE_SUPPORTEDOVENMODES_VALUE_MAX];
        const char *value_heating;
        const char *value_grill;
        const char *value_warming;
        const char *value_defrosting;
        const char *value_Conventional;
        const char *value_Bake;
        const char *value_BottomHeat;
        const char *value_ConvectionBake;
        const char *value_ConvectionRoast;
        const char *value_Broil;
        const char *value_ConvectionBroil;
        const char *value_SteamCook;
        const char *value_SteamBake;
        const char *value_SteamRoast;
        const char *value_SteamBottomHeatplusConvection;
        const char *value_Microwave;
        const char *value_MWplusGrill;
        const char *value_MWplusConvection;
        const char *value_MWplusHotBlast;
        const char *value_MWplusHotBlast2;
        const char *value_SlimMiddle;
        const char *value_SlimStrong;
        const char *value_SlowCook;
        const char *value_Proof;
        const char *value_Dehydrate;
        const char *value_Others;
        const char *value_StrongSteam;
        const char *value_Descale;
        const char *value_Rinse;
    } attr_supportedOvenModes;
    const struct ovenMode_attr_ovenMode {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_OVENMODE_OVENMODE_VALUE_MAX];
        const char *value_heating;
        const char *value_grill;
        const char *value_warming;
        const char *value_defrosting;
        const char *value_Conventional;
        const char *value_Bake;
        const char *value_BottomHeat;
        const char *value_ConvectionBake;
        const char *value_ConvectionRoast;
        const char *value_Broil;
        const char *value_ConvectionBroil;
        const char *value_SteamCook;
        const char *value_SteamBake;
        const char *value_SteamRoast;
        const char *value_SteamBottomHeatplusConvection;
        const char *value_Microwave;
        const char *value_MWplusGrill;
        const char *value_MWplusConvection;
        const char *value_MWplusHotBlast;
        const char *value_MWplusHotBlast2;
        const char *value_SlimMiddle;
        const char *value_SlimStrong;
        const char *value_SlowCook;
        const char *value_Proof;
        const char *value_Dehydrate;
        const char *value_Others;
        const char *value_StrongSteam;
        const char *value_Descale;
        const char *value_Rinse;
    } attr_ovenMode;
    const struct ovenMode_cmd_setOvenMode {
        const char *name;
    } cmd_setOvenMode;
} caps_helper_ovenMode = {
    .id = "ovenMode",
    .attr_supportedOvenModes =
        {
            .name = "supportedOvenModes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"heating",
                       "grill",
                       "warming",
                       "defrosting",
                       "Conventional",
                       "Bake",
                       "BottomHeat",
                       "ConvectionBake",
                       "ConvectionRoast",
                       "Broil",
                       "ConvectionBroil",
                       "SteamCook",
                       "SteamBake",
                       "SteamRoast",
                       "SteamBottomHeatplusConvection",
                       "Microwave",
                       "MWplusGrill",
                       "MWplusConvection",
                       "MWplusHotBlast",
                       "MWplusHotBlast2",
                       "SlimMiddle",
                       "SlimStrong",
                       "SlowCook",
                       "Proof",
                       "Dehydrate",
                       "Others",
                       "StrongSteam",
                       "Descale",
                       "Rinse"},
            .value_heating = "heating",
            .value_grill = "grill",
            .value_warming = "warming",
            .value_defrosting = "defrosting",
            .value_Conventional = "Conventional",
            .value_Bake = "Bake",
            .value_BottomHeat = "BottomHeat",
            .value_ConvectionBake = "ConvectionBake",
            .value_ConvectionRoast = "ConvectionRoast",
            .value_Broil = "Broil",
            .value_ConvectionBroil = "ConvectionBroil",
            .value_SteamCook = "SteamCook",
            .value_SteamBake = "SteamBake",
            .value_SteamRoast = "SteamRoast",
            .value_SteamBottomHeatplusConvection = "SteamBottomHeatplusConvection",
            .value_Microwave = "Microwave",
            .value_MWplusGrill = "MWplusGrill",
            .value_MWplusConvection = "MWplusConvection",
            .value_MWplusHotBlast = "MWplusHotBlast",
            .value_MWplusHotBlast2 = "MWplusHotBlast2",
            .value_SlimMiddle = "SlimMiddle",
            .value_SlimStrong = "SlimStrong",
            .value_SlowCook = "SlowCook",
            .value_Proof = "Proof",
            .value_Dehydrate = "Dehydrate",
            .value_Others = "Others",
            .value_StrongSteam = "StrongSteam",
            .value_Descale = "Descale",
            .value_Rinse = "Rinse",
        },
    .attr_ovenMode =
        {
            .name = "ovenMode",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"heating",
                       "grill",
                       "warming",
                       "defrosting",
                       "Conventional",
                       "Bake",
                       "BottomHeat",
                       "ConvectionBake",
                       "ConvectionRoast",
                       "Broil",
                       "ConvectionBroil",
                       "SteamCook",
                       "SteamBake",
                       "SteamRoast",
                       "SteamBottomHeatplusConvection",
                       "Microwave",
                       "MWplusGrill",
                       "MWplusConvection",
                       "MWplusHotBlast",
                       "MWplusHotBlast2",
                       "SlimMiddle",
                       "SlimStrong",
                       "SlowCook",
                       "Proof",
                       "Dehydrate",
                       "Others",
                       "StrongSteam",
                       "Descale",
                       "Rinse"},
            .value_heating = "heating",
            .value_grill = "grill",
            .value_warming = "warming",
            .value_defrosting = "defrosting",
            .value_Conventional = "Conventional",
            .value_Bake = "Bake",
            .value_BottomHeat = "BottomHeat",
            .value_ConvectionBake = "ConvectionBake",
            .value_ConvectionRoast = "ConvectionRoast",
            .value_Broil = "Broil",
            .value_ConvectionBroil = "ConvectionBroil",
            .value_SteamCook = "SteamCook",
            .value_SteamBake = "SteamBake",
            .value_SteamRoast = "SteamRoast",
            .value_SteamBottomHeatplusConvection = "SteamBottomHeatplusConvection",
            .value_Microwave = "Microwave",
            .value_MWplusGrill = "MWplusGrill",
            .value_MWplusConvection = "MWplusConvection",
            .value_MWplusHotBlast = "MWplusHotBlast",
            .value_MWplusHotBlast2 = "MWplusHotBlast2",
            .value_SlimMiddle = "SlimMiddle",
            .value_SlimStrong = "SlimStrong",
            .value_SlowCook = "SlowCook",
            .value_Proof = "Proof",
            .value_Dehydrate = "Dehydrate",
            .value_Others = "Others",
            .value_StrongSteam = "StrongSteam",
            .value_Descale = "Descale",
            .value_Rinse = "Rinse",
        },
    .cmd_setOvenMode = {.name = "setOvenMode"},  // arguments: mode(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OVEN_MODE_ */

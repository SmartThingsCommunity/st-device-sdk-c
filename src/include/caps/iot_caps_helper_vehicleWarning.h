/* ***************************************************************************
 *
 * Copyright 2026 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_VEHICLE_WARNING_
#define _IOT_CAPS_HELPER_VEHICLE_WARNING_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_VEHICLEWARNING_FUEL_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_FUEL_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_FUEL_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_SMARTKEYBATTERY_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_SMARTKEYBATTERY_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_SMARTKEYBATTERY_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_WASHERFLUID_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_WASHERFLUID_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_WASHERFLUID_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_BRAKEFLUID_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_BRAKEFLUID_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_BRAKEFLUID_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_ENGINEOIL_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_ENGINEOIL_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_ENGINEOIL_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_LAMPWIRE_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_LAMPWIRE_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_LAMPWIRE_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTLEFT_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTLEFT_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTLEFT_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTRIGHT_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTRIGHT_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTRIGHT_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARLEFT_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARLEFT_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARLEFT_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARRIGHT_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARRIGHT_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARRIGHT_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_ELECTRICVEHICLEBATTERY_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_ELECTRICVEHICLEBATTERY_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_ELECTRICVEHICLEBATTERY_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_AUXILIARYBATTERY_VALUE_NORMAL,
    CAP_ENUM_VEHICLEWARNING_AUXILIARYBATTERY_VALUE_WARNING,
    CAP_ENUM_VEHICLEWARNING_AUXILIARYBATTERY_VALUE_MAX
};

enum {
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_FUEL,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_SMARTKEYBATTERY,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_WASHERFLUID,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_BRAKEFLUID,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_ENGINEOIL,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_LAMPWIRE,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_TIREPRESSUREFRONTLEFT,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_TIREPRESSUREFRONTRIGHT,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_TIREPRESSUREREARLEFT,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_TIREPRESSUREREARRIGHT,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_ELECTRICVEHICLEBATTERY,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_AUXILIARYBATTERY,
    CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_MAX
};

const static struct iot_caps_vehicleWarning {
    const char *id;
    const struct vehicleWarning_attr_fuel {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_FUEL_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_fuel;
    const struct vehicleWarning_attr_smartKeyBattery {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_SMARTKEYBATTERY_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_smartKeyBattery;
    const struct vehicleWarning_attr_washerFluid {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_WASHERFLUID_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_washerFluid;
    const struct vehicleWarning_attr_brakeFluid {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_BRAKEFLUID_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_brakeFluid;
    const struct vehicleWarning_attr_engineOil {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_ENGINEOIL_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_engineOil;
    const struct vehicleWarning_attr_lampWire {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_LAMPWIRE_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_lampWire;
    const struct vehicleWarning_attr_tirePressureFrontLeft {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTLEFT_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_tirePressureFrontLeft;
    const struct vehicleWarning_attr_tirePressureFrontRight {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_TIREPRESSUREFRONTRIGHT_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_tirePressureFrontRight;
    const struct vehicleWarning_attr_tirePressureRearLeft {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARLEFT_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_tirePressureRearLeft;
    const struct vehicleWarning_attr_tirePressureRearRight {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_TIREPRESSUREREARRIGHT_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_tirePressureRearRight;
    const struct vehicleWarning_attr_electricVehicleBattery {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_ELECTRICVEHICLEBATTERY_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_electricVehicleBattery;
    const struct vehicleWarning_attr_auxiliaryBattery {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_AUXILIARYBATTERY_VALUE_MAX];
        const char *value_normal;
        const char *value_warning;
    } attr_auxiliaryBattery;
    const struct vehicleWarning_attr_supportedAttributes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_VEHICLEWARNING_SUPPORTEDATTRIBUTES_VALUE_MAX];
        const char *value_fuel;
        const char *value_smartKeyBattery;
        const char *value_washerFluid;
        const char *value_brakeFluid;
        const char *value_engineOil;
        const char *value_lampWire;
        const char *value_tirePressureFrontLeft;
        const char *value_tirePressureFrontRight;
        const char *value_tirePressureRearLeft;
        const char *value_tirePressureRearRight;
        const char *value_electricVehicleBattery;
        const char *value_auxiliaryBattery;
    } attr_supportedAttributes;
} caps_helper_vehicleWarning = {
    .id = "vehicleWarning",
    .attr_fuel =
        {
            .name = "fuel",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_smartKeyBattery =
        {
            .name = "smartKeyBattery",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_washerFluid =
        {
            .name = "washerFluid",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_brakeFluid =
        {
            .name = "brakeFluid",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_engineOil =
        {
            .name = "engineOil",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_lampWire =
        {
            .name = "lampWire",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_tirePressureFrontLeft =
        {
            .name = "tirePressureFrontLeft",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_tirePressureFrontRight =
        {
            .name = "tirePressureFrontRight",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_tirePressureRearLeft =
        {
            .name = "tirePressureRearLeft",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_tirePressureRearRight =
        {
            .name = "tirePressureRearRight",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_electricVehicleBattery =
        {
            .name = "electricVehicleBattery",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_auxiliaryBattery =
        {
            .name = "auxiliaryBattery",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"normal", "warning"},
            .value_normal = "normal",
            .value_warning = "warning",
        },
    .attr_supportedAttributes =
        {
            .name = "supportedAttributes",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"fuel", "smartKeyBattery", "washerFluid", "brakeFluid", "engineOil", "lampWire",
                       "tirePressureFrontLeft", "tirePressureFrontRight", "tirePressureRearLeft",
                       "tirePressureRearRight", "electricVehicleBattery", "auxiliaryBattery"},
            .value_fuel = "fuel",
            .value_smartKeyBattery = "smartKeyBattery",
            .value_washerFluid = "washerFluid",
            .value_brakeFluid = "brakeFluid",
            .value_engineOil = "engineOil",
            .value_lampWire = "lampWire",
            .value_tirePressureFrontLeft = "tirePressureFrontLeft",
            .value_tirePressureFrontRight = "tirePressureFrontRight",
            .value_tirePressureRearLeft = "tirePressureRearLeft",
            .value_tirePressureRearRight = "tirePressureRearRight",
            .value_electricVehicleBattery = "electricVehicleBattery",
            .value_auxiliaryBattery = "auxiliaryBattery",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_VEHICLE_WARNING_ */

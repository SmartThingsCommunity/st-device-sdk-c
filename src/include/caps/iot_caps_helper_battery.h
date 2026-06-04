/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_BATTERY_
#define _IOT_CAPS_HELPER_BATTERY_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CAP_ENUM_BATTERY_BATTERY_UNIT_PERCENT, CAP_ENUM_BATTERY_BATTERY_UNIT_MAX };

enum {
    CAP_ENUM_BATTERY_TYPE_VALUE_UNSPECIFIED,
    CAP_ENUM_BATTERY_TYPE_VALUE_CUSTOMED,
    CAP_ENUM_BATTERY_TYPE_VALUE_AAA,
    CAP_ENUM_BATTERY_TYPE_VALUE_AA,
    CAP_ENUM_BATTERY_TYPE_VALUE_C,
    CAP_ENUM_BATTERY_TYPE_VALUE_D,
    CAP_ENUM_BATTERY_TYPE_VALUE_4V5,
    CAP_ENUM_BATTERY_TYPE_VALUE_6V0,
    CAP_ENUM_BATTERY_TYPE_VALUE_9V0,
    CAP_ENUM_BATTERY_TYPE_VALUE_1_2AA,
    CAP_ENUM_BATTERY_TYPE_VALUE_AAAA,
    CAP_ENUM_BATTERY_TYPE_VALUE_A,
    CAP_ENUM_BATTERY_TYPE_VALUE_B,
    CAP_ENUM_BATTERY_TYPE_VALUE_F,
    CAP_ENUM_BATTERY_TYPE_VALUE_N,
    CAP_ENUM_BATTERY_TYPE_VALUE_NO6,
    CAP_ENUM_BATTERY_TYPE_VALUE_SUBC,
    CAP_ENUM_BATTERY_TYPE_VALUE_A23,
    CAP_ENUM_BATTERY_TYPE_VALUE_A27,
    CAP_ENUM_BATTERY_TYPE_VALUE_BA5800,
    CAP_ENUM_BATTERY_TYPE_VALUE_DUPLEX,
    CAP_ENUM_BATTERY_TYPE_VALUE_4SR44,
    CAP_ENUM_BATTERY_TYPE_VALUE_523,
    CAP_ENUM_BATTERY_TYPE_VALUE_531,
    CAP_ENUM_BATTERY_TYPE_VALUE_15V0,
    CAP_ENUM_BATTERY_TYPE_VALUE_22V5,
    CAP_ENUM_BATTERY_TYPE_VALUE_30V0,
    CAP_ENUM_BATTERY_TYPE_VALUE_45V0,
    CAP_ENUM_BATTERY_TYPE_VALUE_67V5,
    CAP_ENUM_BATTERY_TYPE_VALUE_J,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR123A,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2,
    CAP_ENUM_BATTERY_TYPE_VALUE_2CR5,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR_P2,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR_V3,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR41,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR42,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR43,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR44,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR45,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR48,
    CAP_ENUM_BATTERY_TYPE_VALUE_LR52,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR54,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR55,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR56,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR57,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR58,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR59,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR60,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR62,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR63,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR64,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR65,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR66,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR67,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR68,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR69,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR416,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR512,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR516,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR731,
    CAP_ENUM_BATTERY_TYPE_VALUE_SR712,
    CAP_ENUM_BATTERY_TYPE_VALUE_LR932,
    CAP_ENUM_BATTERY_TYPE_VALUE_LR9,
    CAP_ENUM_BATTERY_TYPE_VALUE_A5,
    CAP_ENUM_BATTERY_TYPE_VALUE_A10,
    CAP_ENUM_BATTERY_TYPE_VALUE_A13,
    CAP_ENUM_BATTERY_TYPE_VALUE_A312,
    CAP_ENUM_BATTERY_TYPE_VALUE_A675,
    CAP_ENUM_BATTERY_TYPE_VALUE_AC41E,
    CAP_ENUM_BATTERY_TYPE_VALUE_7540,
    CAP_ENUM_BATTERY_TYPE_VALUE_8570,
    CAP_ENUM_BATTERY_TYPE_VALUE_10180,
    CAP_ENUM_BATTERY_TYPE_VALUE_10280,
    CAP_ENUM_BATTERY_TYPE_VALUE_10440,
    CAP_ENUM_BATTERY_TYPE_VALUE_10850,
    CAP_ENUM_BATTERY_TYPE_VALUE_13400,
    CAP_ENUM_BATTERY_TYPE_VALUE_14250,
    CAP_ENUM_BATTERY_TYPE_VALUE_14300,
    CAP_ENUM_BATTERY_TYPE_VALUE_14430,
    CAP_ENUM_BATTERY_TYPE_VALUE_14500,
    CAP_ENUM_BATTERY_TYPE_VALUE_14650,
    CAP_ENUM_BATTERY_TYPE_VALUE_15270,
    CAP_ENUM_BATTERY_TYPE_VALUE_16340,
    CAP_ENUM_BATTERY_TYPE_VALUE_16650,
    CAP_ENUM_BATTERY_TYPE_VALUE_RCR123A,
    CAP_ENUM_BATTERY_TYPE_VALUE_17500,
    CAP_ENUM_BATTERY_TYPE_VALUE_17650,
    CAP_ENUM_BATTERY_TYPE_VALUE_17670,
    CAP_ENUM_BATTERY_TYPE_VALUE_18350,
    CAP_ENUM_BATTERY_TYPE_VALUE_18490,
    CAP_ENUM_BATTERY_TYPE_VALUE_18500,
    CAP_ENUM_BATTERY_TYPE_VALUE_18650,
    CAP_ENUM_BATTERY_TYPE_VALUE_19670,
    CAP_ENUM_BATTERY_TYPE_VALUE_20700,
    CAP_ENUM_BATTERY_TYPE_VALUE_21700,
    CAP_ENUM_BATTERY_TYPE_VALUE_25500,
    CAP_ENUM_BATTERY_TYPE_VALUE_26500,
    CAP_ENUM_BATTERY_TYPE_VALUE_26650,
    CAP_ENUM_BATTERY_TYPE_VALUE_26700,
    CAP_ENUM_BATTERY_TYPE_VALUE_26800,
    CAP_ENUM_BATTERY_TYPE_VALUE_32600,
    CAP_ENUM_BATTERY_TYPE_VALUE_32650,
    CAP_ENUM_BATTERY_TYPE_VALUE_32700,
    CAP_ENUM_BATTERY_TYPE_VALUE_38120,
    CAP_ENUM_BATTERY_TYPE_VALUE_38140,
    CAP_ENUM_BATTERY_TYPE_VALUE_40152,
    CAP_ENUM_BATTERY_TYPE_VALUE_4680,
    CAP_ENUM_BATTERY_TYPE_VALUE_4695,
    CAP_ENUM_BATTERY_TYPE_VALUE_46120,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP1,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP3,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP4,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP6,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP7,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP8,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP9,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP10,
    CAP_ENUM_BATTERY_TYPE_VALUE_PP11,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR927,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1025,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1130,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1216,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1220,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1225,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1616,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1620,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR1632,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2012,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2016,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2020,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2025,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2032,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2040,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2050,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2320,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2325,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2330,
    CAP_ENUM_BATTERY_TYPE_VALUE_BR2335,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2354,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2412,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2430,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2450,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR2477,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR3032,
    CAP_ENUM_BATTERY_TYPE_VALUE_CR11108,
    CAP_ENUM_BATTERY_TYPE_VALUE_MAX
};

const static struct iot_caps_battery {
    const char *id;
    const struct battery_attr_quantity {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_quantity;
    const struct battery_attr_battery {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *units[CAP_ENUM_BATTERY_BATTERY_UNIT_MAX];
        const char *unit_percent;
        const int min;
        const int max;
    } attr_battery;
    const struct battery_attr_type {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_BATTERY_TYPE_VALUE_MAX];
    } attr_type;
} caps_helper_battery = {
    .id = "battery",
    .attr_quantity =
        {
            .name = "quantity",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .min = 0,
        },
    .attr_battery =
        {
            .name = "battery",
            .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_MAX | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_INTEGER,
            .units = {"%"},
            .unit_percent = "%",
            .min = 0,
            .max = 100,
        },
    .attr_type =
        {
            .name = "type",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"Unspecified", "Customed", "AAA",    "AA",     "C",       "D",      "4v5",    "6v0",    "9v0",
                       "1_2AA",       "AAAA",     "A",      "B",      "F",       "N",      "No6",    "SubC",   "A23",
                       "A27",         "BA5800",   "Duplex", "4SR44",  "523",     "531",    "15v0",   "22v5",   "30v0",
                       "45v0",        "67v5",     "J",      "CR123A", "CR2",     "2CR5",   "CR_P2",  "CR_V3",  "SR41",
                       "SR42",        "SR43",     "SR44",   "SR45",   "SR48",    "LR52",   "SR54",   "SR55",   "SR56",
                       "SR57",        "SR58",     "SR59",   "SR60",   "SR62",    "SR63",   "SR64",   "SR65",   "SR66",
                       "SR67",        "SR68",     "SR69",   "SR416",  "SR512",   "SR516",  "SR731",  "SR712",  "LR932",
                       "LR9",         "A5",       "A10",    "A13",    "A312",    "A675",   "AC41E",  "7540",   "8570",
                       "10180",       "10280",    "10440",  "10850",  "13400",   "14250",  "14300",  "14430",  "14500",
                       "14650",       "15270",    "16340",  "16650",  "RCR123A", "17500",  "17650",  "17670",  "18350",
                       "18490",       "18500",    "18650",  "19670",  "20700",   "21700",  "25500",  "26500",  "26650",
                       "26700",       "26800",    "32600",  "32650",  "32700",   "38120",  "38140",  "40152",  "4680",
                       "4695",        "46120",    "PP1",    "PP3",    "PP4",     "PP6",    "PP7",    "PP8",    "PP9",
                       "PP10",        "PP11",     "CR927",  "CR1025", "CR1130",  "CR1216", "CR1220", "CR1225", "CR1616",
                       "CR1620",      "CR1632",   "CR2012", "CR2016", "CR2020",  "CR2025", "CR2032", "CR2040", "CR2050",
                       "CR2320",      "CR2325",   "CR2330", "BR2335", "CR2354",  "CR2412", "CR2430", "CR2450", "CR2477",
                       "CR3032",      "CR11108"},
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_BATTERY_ */

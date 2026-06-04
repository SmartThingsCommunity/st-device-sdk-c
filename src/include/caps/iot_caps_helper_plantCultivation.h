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

#ifndef _IOT_CAPS_HELPER_PLANT_CULTIVATION_
#define _IOT_CAPS_HELPER_PLANT_CULTIVATION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_NONE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LETTUCE_CAESARSGREEN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LETTUCE_JEOKOAK,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_TATSOI_VITAMIN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_COLLARDLEAFKALE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LEAFREDCHICORY,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_GARLANDCHRYSANTHEMUM,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PAKCHOI,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LEAFMUSTARD,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_BASIL,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_RUCOLA,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_CILANTRO,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_DILL,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_THYME,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LEMONBALM,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_CATNIP,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_ENDIVE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LETTUCE_MULTIGREEN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_NAPACABBAGE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_APPLEMINT,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_THAIBASIL,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PEPPERMINT,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_BURNINGBUSHSPINDLETREE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LOLLOBIONDA_BARTIMER,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LETTUCE_MINIROMAINE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_NEWGREEN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_REDVEINEDSORREL,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_SAGE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_EGGPLANT,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PEPPER,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_STRAWBERRY,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_ROSEMARY,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_MONSTERA,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_MINT,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_CHERRYTOMATO,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_GARLICCHIVES,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_SANSEVIERIA,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_LETTUCE,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PEACELILY,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PARSLEY,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PAPRIKA,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PEPEROMIA,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PHILODENDRON,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_PARSLEY_ITALIAN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_UNKNOWN,
    CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_MAX
};

enum {
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_NONE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LETTUCE_CAESARSGREEN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LETTUCE_JEOKOAK,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_TATSOI_VITAMIN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_COLLARDLEAFKALE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LEAFREDCHICORY,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_GARLANDCHRYSANTHEMUM,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PAKCHOI,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LEAFMUSTARD,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_BASIL,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_RUCOLA,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_CILANTRO,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_DILL,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_THYME,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LEMONBALM,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_CATNIP,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_ENDIVE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LETTUCE_MULTIGREEN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_NAPACABBAGE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_APPLEMINT,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_THAIBASIL,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PEPPERMINT,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_BURNINGBUSHSPINDLETREE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LOLLOBIONDA_BARTIMER,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LETTUCE_MINIROMAINE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_NEWGREEN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_REDVEINEDSORREL,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_SAGE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_EGGPLANT,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PEPPER,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_STRAWBERRY,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_ROSEMARY,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_MONSTERA,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_MINT,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_CHERRYTOMATO,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_GARLICCHIVES,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_SANSEVIERIA,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_LETTUCE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PEACELILY,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PARSLEY,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PAPRIKA,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PEPEROMIA,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PHILODENDRON,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_PARSLEY_ITALIAN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_UNKNOWN,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_MAX
};

enum {
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDCOMMANDS_VALUE_SETPLANTTYPE,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDCOMMANDS_VALUE_RESETSTARTTIME,
    CAP_ENUM_PLANTCULTIVATION_SUPPORTEDCOMMANDS_VALUE_MAX
};

const static struct iot_caps_plantCultivation {
    const char *id;
    const struct plantCultivation_attr_plantType {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PLANTCULTIVATION_PLANTTYPE_VALUE_MAX];
        const char *value_none;
        const char *value_lettuce_caesarsGreen;
        const char *value_lettuce_jeokOak;
        const char *value_tatsoi_vitamin;
        const char *value_collardLeafKale;
        const char *value_leafRedChicory;
        const char *value_garlandChrysanthemum;
        const char *value_pakchoi;
        const char *value_leafMustard;
        const char *value_basil;
        const char *value_rucola;
        const char *value_cilantro;
        const char *value_dill;
        const char *value_thyme;
        const char *value_lemonBalm;
        const char *value_catnip;
        const char *value_endive;
        const char *value_lettuce_multiGreen;
        const char *value_napaCabbage;
        const char *value_appleMint;
        const char *value_thaiBasil;
        const char *value_peppermint;
        const char *value_burningBushSpindletree;
        const char *value_lolloBionda_Bartimer;
        const char *value_lettuce_miniRomaine;
        const char *value_newGreen;
        const char *value_redVeinedSorrel;
        const char *value_sage;
        const char *value_eggplant;
        const char *value_pepper;
        const char *value_strawberry;
        const char *value_rosemary;
        const char *value_monstera;
        const char *value_mint;
        const char *value_cherryTomato;
        const char *value_garlicChives;
        const char *value_sansevieria;
        const char *value_lettuce;
        const char *value_peaceLily;
        const char *value_parsley;
        const char *value_paprika;
        const char *value_peperomia;
        const char *value_philodendron;
        const char *value_parsley_italian;
        const char *value_UNKNOWN;
    } attr_plantType;
    const struct plantCultivation_attr_supportedPlantType {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PLANTCULTIVATION_SUPPORTEDPLANTTYPE_VALUE_MAX];
        const char *value_none;
        const char *value_lettuce_caesarsGreen;
        const char *value_lettuce_jeokOak;
        const char *value_tatsoi_vitamin;
        const char *value_collardLeafKale;
        const char *value_leafRedChicory;
        const char *value_garlandChrysanthemum;
        const char *value_pakchoi;
        const char *value_leafMustard;
        const char *value_basil;
        const char *value_rucola;
        const char *value_cilantro;
        const char *value_dill;
        const char *value_thyme;
        const char *value_lemonBalm;
        const char *value_catnip;
        const char *value_endive;
        const char *value_lettuce_multiGreen;
        const char *value_napaCabbage;
        const char *value_appleMint;
        const char *value_thaiBasil;
        const char *value_peppermint;
        const char *value_burningBushSpindletree;
        const char *value_lolloBionda_Bartimer;
        const char *value_lettuce_miniRomaine;
        const char *value_newGreen;
        const char *value_redVeinedSorrel;
        const char *value_sage;
        const char *value_eggplant;
        const char *value_pepper;
        const char *value_strawberry;
        const char *value_rosemary;
        const char *value_monstera;
        const char *value_mint;
        const char *value_cherryTomato;
        const char *value_garlicChives;
        const char *value_sansevieria;
        const char *value_lettuce;
        const char *value_peaceLily;
        const char *value_parsley;
        const char *value_paprika;
        const char *value_peperomia;
        const char *value_philodendron;
        const char *value_parsley_italian;
        const char *value_UNKNOWN;
    } attr_supportedPlantType;
    const struct plantCultivation_attr_startTime {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_startTime;
    const struct plantCultivation_attr_supportedCommands {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_PLANTCULTIVATION_SUPPORTEDCOMMANDS_VALUE_MAX];
        const char *value_setPlantType;
        const char *value_resetStartTime;
    } attr_supportedCommands;
    const struct plantCultivation_cmd_setPlantType {
        const char *name;
    } cmd_setPlantType;
    const struct plantCultivation_cmd_resetStartTime {
        const char *name;
    } cmd_resetStartTime;
} caps_helper_plantCultivation = {
    .id = "plantCultivation",
    .attr_plantType =
        {
            .name = "plantType",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"none",
                       "lettuce_caesarsGreen",
                       "lettuce_jeokOak",
                       "tatsoi_vitamin",
                       "collardLeafKale",
                       "leafRedChicory",
                       "garlandChrysanthemum",
                       "pakchoi",
                       "leafMustard",
                       "basil",
                       "rucola",
                       "cilantro",
                       "dill",
                       "thyme",
                       "lemonBalm",
                       "catnip",
                       "endive",
                       "lettuce_multiGreen",
                       "napaCabbage",
                       "appleMint",
                       "thaiBasil",
                       "peppermint",
                       "burningBushSpindletree",
                       "lolloBionda_Bartimer",
                       "lettuce_miniRomaine",
                       "newGreen",
                       "redVeinedSorrel",
                       "sage",
                       "eggplant",
                       "pepper",
                       "strawberry",
                       "rosemary",
                       "monstera",
                       "mint",
                       "cherryTomato",
                       "garlicChives",
                       "sansevieria",
                       "lettuce",
                       "peaceLily",
                       "parsley",
                       "paprika",
                       "peperomia",
                       "philodendron",
                       "parsley_italian",
                       "UNKNOWN"},
            .value_none = "none",
            .value_lettuce_caesarsGreen = "lettuce_caesarsGreen",
            .value_lettuce_jeokOak = "lettuce_jeokOak",
            .value_tatsoi_vitamin = "tatsoi_vitamin",
            .value_collardLeafKale = "collardLeafKale",
            .value_leafRedChicory = "leafRedChicory",
            .value_garlandChrysanthemum = "garlandChrysanthemum",
            .value_pakchoi = "pakchoi",
            .value_leafMustard = "leafMustard",
            .value_basil = "basil",
            .value_rucola = "rucola",
            .value_cilantro = "cilantro",
            .value_dill = "dill",
            .value_thyme = "thyme",
            .value_lemonBalm = "lemonBalm",
            .value_catnip = "catnip",
            .value_endive = "endive",
            .value_lettuce_multiGreen = "lettuce_multiGreen",
            .value_napaCabbage = "napaCabbage",
            .value_appleMint = "appleMint",
            .value_thaiBasil = "thaiBasil",
            .value_peppermint = "peppermint",
            .value_burningBushSpindletree = "burningBushSpindletree",
            .value_lolloBionda_Bartimer = "lolloBionda_Bartimer",
            .value_lettuce_miniRomaine = "lettuce_miniRomaine",
            .value_newGreen = "newGreen",
            .value_redVeinedSorrel = "redVeinedSorrel",
            .value_sage = "sage",
            .value_eggplant = "eggplant",
            .value_pepper = "pepper",
            .value_strawberry = "strawberry",
            .value_rosemary = "rosemary",
            .value_monstera = "monstera",
            .value_mint = "mint",
            .value_cherryTomato = "cherryTomato",
            .value_garlicChives = "garlicChives",
            .value_sansevieria = "sansevieria",
            .value_lettuce = "lettuce",
            .value_peaceLily = "peaceLily",
            .value_parsley = "parsley",
            .value_paprika = "paprika",
            .value_peperomia = "peperomia",
            .value_philodendron = "philodendron",
            .value_parsley_italian = "parsley_italian",
            .value_UNKNOWN = "UNKNOWN",
        },
    .attr_supportedPlantType =
        {
            .name = "supportedPlantType",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"none",
                       "lettuce_caesarsGreen",
                       "lettuce_jeokOak",
                       "tatsoi_vitamin",
                       "collardLeafKale",
                       "leafRedChicory",
                       "garlandChrysanthemum",
                       "pakchoi",
                       "leafMustard",
                       "basil",
                       "rucola",
                       "cilantro",
                       "dill",
                       "thyme",
                       "lemonBalm",
                       "catnip",
                       "endive",
                       "lettuce_multiGreen",
                       "napaCabbage",
                       "appleMint",
                       "thaiBasil",
                       "peppermint",
                       "burningBushSpindletree",
                       "lolloBionda_Bartimer",
                       "lettuce_miniRomaine",
                       "newGreen",
                       "redVeinedSorrel",
                       "sage",
                       "eggplant",
                       "pepper",
                       "strawberry",
                       "rosemary",
                       "monstera",
                       "mint",
                       "cherryTomato",
                       "garlicChives",
                       "sansevieria",
                       "lettuce",
                       "peaceLily",
                       "parsley",
                       "paprika",
                       "peperomia",
                       "philodendron",
                       "parsley_italian",
                       "UNKNOWN"},
            .value_none = "none",
            .value_lettuce_caesarsGreen = "lettuce_caesarsGreen",
            .value_lettuce_jeokOak = "lettuce_jeokOak",
            .value_tatsoi_vitamin = "tatsoi_vitamin",
            .value_collardLeafKale = "collardLeafKale",
            .value_leafRedChicory = "leafRedChicory",
            .value_garlandChrysanthemum = "garlandChrysanthemum",
            .value_pakchoi = "pakchoi",
            .value_leafMustard = "leafMustard",
            .value_basil = "basil",
            .value_rucola = "rucola",
            .value_cilantro = "cilantro",
            .value_dill = "dill",
            .value_thyme = "thyme",
            .value_lemonBalm = "lemonBalm",
            .value_catnip = "catnip",
            .value_endive = "endive",
            .value_lettuce_multiGreen = "lettuce_multiGreen",
            .value_napaCabbage = "napaCabbage",
            .value_appleMint = "appleMint",
            .value_thaiBasil = "thaiBasil",
            .value_peppermint = "peppermint",
            .value_burningBushSpindletree = "burningBushSpindletree",
            .value_lolloBionda_Bartimer = "lolloBionda_Bartimer",
            .value_lettuce_miniRomaine = "lettuce_miniRomaine",
            .value_newGreen = "newGreen",
            .value_redVeinedSorrel = "redVeinedSorrel",
            .value_sage = "sage",
            .value_eggplant = "eggplant",
            .value_pepper = "pepper",
            .value_strawberry = "strawberry",
            .value_rosemary = "rosemary",
            .value_monstera = "monstera",
            .value_mint = "mint",
            .value_cherryTomato = "cherryTomato",
            .value_garlicChives = "garlicChives",
            .value_sansevieria = "sansevieria",
            .value_lettuce = "lettuce",
            .value_peaceLily = "peaceLily",
            .value_parsley = "parsley",
            .value_paprika = "paprika",
            .value_peperomia = "peperomia",
            .value_philodendron = "philodendron",
            .value_parsley_italian = "parsley_italian",
            .value_UNKNOWN = "UNKNOWN",
        },
    .attr_startTime =
        {
            .name = "startTime",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
        },
    .attr_supportedCommands =
        {
            .name = "supportedCommands",
            .property = ATTR_SET_VALUE_ARRAY | ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"setPlantType", "resetStartTime"},
            .value_setPlantType = "setPlantType",
            .value_resetStartTime = "resetStartTime",
        },
    .cmd_setPlantType = {.name = "setPlantType"},      // arguments: plantType(string)
    .cmd_resetStartTime = {.name = "resetStartTime"},  // arguments: time(string)
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_PLANT_CULTIVATION_ */

/* ***************************************************************************
 *
 * Copyright 2019-2021 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_SOUND_DETECTION_
#define _IOT_CAPS_HELPER_SOUND_DETECTION_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_ENUM_SOUNDDETECTION_SUPPORTEDSOUNDTYPES_VALUE_MAX 23
enum {
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_NOSOUND,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_BABYCRYING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_GLASSBREAKING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_FIREALARM,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_APPLIANCEALARM,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_EMERGENCYALARM,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_SCREAMING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_DOGBARKING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_DOGGROWLING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_DOGHOWLING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_CATMEOWING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_CATPURRING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_DOORKNOCKING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_DOORBELL,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_FAUCETRUNNING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_HAIRDRYING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_KETTLEBOILING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_SIREN,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_FINGERSNAPPING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_CLAPPING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_COUGHING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_SPEECH,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_SNORING,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_MAX
};

enum {
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTIONSTATE_VALUE_ENABLED,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTIONSTATE_VALUE_DISABLED,
    CAP_ENUM_SOUNDDETECTION_SOUNDDETECTIONSTATE_VALUE_MAX
};

const static struct iot_caps_soundDetection {
    const char *id;
    const struct soundDetection_attr_soundDetected {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SOUNDDETECTION_SOUNDDETECTED_VALUE_MAX];
        const char *value_noSound;
        const char *value_babyCrying;
        const char *value_glassBreaking;
        const char *value_fireAlarm;
        const char *value_applianceAlarm;
        const char *value_emergencyAlarm;
        const char *value_screaming;
        const char *value_dogBarking;
        const char *value_dogGrowling;
        const char *value_dogHowling;
        const char *value_catMeowing;
        const char *value_catPurring;
        const char *value_doorKnocking;
        const char *value_doorbell;
        const char *value_faucetRunning;
        const char *value_hairDrying;
        const char *value_kettleBoiling;
        const char *value_siren;
        const char *value_fingerSnapping;
        const char *value_clapping;
        const char *value_coughing;
        const char *value_speech;
        const char *value_snoring;
    } attr_soundDetected;
    const struct soundDetection_attr_soundDetectionState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SOUNDDETECTION_SOUNDDETECTIONSTATE_VALUE_MAX];
        const char *value_enabled;
        const char *value_disabled;
    } attr_soundDetectionState;
    const struct soundDetection_attr_supportedSoundTypes {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_SOUNDDETECTION_SUPPORTEDSOUNDTYPES_VALUE_MAX];
        const char *value_noSound;
        const char *value_babyCrying;
        const char *value_glassBreaking;
        const char *value_fireAlarm;
        const char *value_applianceAlarm;
        const char *value_emergencyAlarm;
        const char *value_screaming;
        const char *value_dogBarking;
        const char *value_dogGrowling;
        const char *value_dogHowling;
        const char *value_catMeowing;
        const char *value_catPurring;
        const char *value_doorKnocking;
        const char *value_doorbell;
        const char *value_faucetRunning;
        const char *value_hairDrying;
        const char *value_kettleBoiling;
        const char *value_siren;
        const char *value_fingerSnapping;
        const char *value_clapping;
        const char *value_coughing;
        const char *value_speech;
        const char *value_snoring;
    } attr_supportedSoundTypes;
    const struct soundDetection_cmd_enableSoundDetection {
        const char *name;
    } cmd_enableSoundDetection;
    const struct soundDetection_cmd_disableSoundDetection {
        const char *name;
    } cmd_disableSoundDetection;
} caps_helper_soundDetection = {
    .id = "soundDetection",
    .attr_soundDetected =
        {
            .name = "soundDetected",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noSound",        "babyCrying",    "glassBreaking", "fireAlarm",      "applianceAlarm",
                       "emergencyAlarm", "screaming",     "dogBarking",    "dogGrowling",    "dogHowling",
                       "catMeowing",     "catPurring",    "doorKnocking",  "doorbell",       "faucetRunning",
                       "hairDrying",     "kettleBoiling", "siren",         "fingerSnapping", "clapping",
                       "coughing",       "speech",        "snoring"},
            .value_noSound = "noSound",
            .value_babyCrying = "babyCrying",
            .value_glassBreaking = "glassBreaking",
            .value_fireAlarm = "fireAlarm",
            .value_applianceAlarm = "applianceAlarm",
            .value_emergencyAlarm = "emergencyAlarm",
            .value_screaming = "screaming",
            .value_dogBarking = "dogBarking",
            .value_dogGrowling = "dogGrowling",
            .value_dogHowling = "dogHowling",
            .value_catMeowing = "catMeowing",
            .value_catPurring = "catPurring",
            .value_doorKnocking = "doorKnocking",
            .value_doorbell = "doorbell",
            .value_faucetRunning = "faucetRunning",
            .value_hairDrying = "hairDrying",
            .value_kettleBoiling = "kettleBoiling",
            .value_siren = "siren",
            .value_fingerSnapping = "fingerSnapping",
            .value_clapping = "clapping",
            .value_coughing = "coughing",
            .value_speech = "speech",
            .value_snoring = "snoring",
        },
    .attr_soundDetectionState =
        {
            .name = "soundDetectionState",
            .property = 0,
            .valueType = VALUE_TYPE_STRING,
            .values = {"enabled", "disabled"},
            .value_enabled = "enabled",
            .value_disabled = "disabled",
        },
    .attr_supportedSoundTypes =
        {
            .name = "supportedSoundTypes",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"noSound",        "babyCrying",    "glassBreaking", "fireAlarm",      "applianceAlarm",
                       "emergencyAlarm", "screaming",     "dogBarking",    "dogGrowling",    "dogHowling",
                       "catMeowing",     "catPurring",    "doorKnocking",  "doorbell",       "faucetRunning",
                       "hairDrying",     "kettleBoiling", "siren",         "fingerSnapping", "clapping",
                       "coughing",       "speech",        "snoring"},
            .value_noSound = "noSound",
            .value_babyCrying = "babyCrying",
            .value_glassBreaking = "glassBreaking",
            .value_fireAlarm = "fireAlarm",
            .value_applianceAlarm = "applianceAlarm",
            .value_emergencyAlarm = "emergencyAlarm",
            .value_screaming = "screaming",
            .value_dogBarking = "dogBarking",
            .value_dogGrowling = "dogGrowling",
            .value_dogHowling = "dogHowling",
            .value_catMeowing = "catMeowing",
            .value_catPurring = "catPurring",
            .value_doorKnocking = "doorKnocking",
            .value_doorbell = "doorbell",
            .value_faucetRunning = "faucetRunning",
            .value_hairDrying = "hairDrying",
            .value_kettleBoiling = "kettleBoiling",
            .value_siren = "siren",
            .value_fingerSnapping = "fingerSnapping",
            .value_clapping = "clapping",
            .value_coughing = "coughing",
            .value_speech = "speech",
            .value_snoring = "snoring",
        },
    .cmd_enableSoundDetection = {.name = "enableSoundDetection"},
    .cmd_disableSoundDetection = {.name = "disableSoundDetection"},
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HELPER_SOUND_DETECTION_ */

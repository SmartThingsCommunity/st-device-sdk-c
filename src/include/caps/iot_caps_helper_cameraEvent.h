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

#ifndef _IOT_CAPS_HELPER_CAMERA_EVENT_
#define _IOT_CAPS_HELPER_CAMERA_EVENT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PACKAGE,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PACKAGEDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PERSON,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PERSONDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_VEHICLE,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_VEHICLEDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PET,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_PETDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_LOITERING,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_LOITERINGDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_GESTUREV,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_GESTUREFOUR,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_GESTUREFIVE,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_GESTUREGUN,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_GESTUREOK,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_LENSOBSTRUCTION,
    CAP_ENUM_CAMERAEVENT_EVENT_VALUE_MAX
};

enum {
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PACKAGE,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PACKAGEDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PERSON,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PERSONDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_VEHICLE,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_VEHICLEDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PET,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_PETDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_LOITERING,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_LOITERINGDISAPPEAR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_GESTUREV,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_GESTUREFOUR,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_GESTUREFIVE,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_GESTUREGUN,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_GESTUREOK,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_LENSOBSTRUCTION,
    CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_MAX
};

const static struct iot_caps_cameraEvent {
    const char *id;
    const struct cameraEvent_attr_event {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAEVENT_EVENT_VALUE_MAX];
        const char *value_package;
        const char *value_packageDisappear;
        const char *value_person;
        const char *value_personDisappear;
        const char *value_vehicle;
        const char *value_vehicleDisappear;
        const char *value_pet;
        const char *value_petDisappear;
        const char *value_loitering;
        const char *value_loiteringDisappear;
        const char *value_gestureV;
        const char *value_gestureFour;
        const char *value_gestureFive;
        const char *value_gestureGun;
        const char *value_gestureOk;
        const char *value_lensObstruction;
    } attr_event;
    const struct cameraEvent_attr_supportedEvents {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_CAMERAEVENT_SUPPORTEDEVENTS_VALUE_MAX];
        const char *value_package;
        const char *value_packageDisappear;
        const char *value_person;
        const char *value_personDisappear;
        const char *value_vehicle;
        const char *value_vehicleDisappear;
        const char *value_pet;
        const char *value_petDisappear;
        const char *value_loitering;
        const char *value_loiteringDisappear;
        const char *value_gestureV;
        const char *value_gestureFour;
        const char *value_gestureFive;
        const char *value_gestureGun;
        const char *value_gestureOk;
        const char *value_lensObstruction;
    } attr_supportedEvents;
} caps_helper_cameraEvent = {
    .id = "cameraEvent",
    .attr_event =
        {
            .name = "event",
            .property = ATTR_SET_VALUE_REQUIRED,
            .valueType = VALUE_TYPE_STRING,
            .values = {"package", "packageDisappear", "person", "personDisappear", "vehicle", "vehicleDisappear", "pet",
                       "petDisappear", "loitering", "loiteringDisappear", "gestureV", "gestureFour", "gestureFive",
                       "gestureGun", "gestureOk", "lensObstruction"},
            .value_package = "package",
            .value_packageDisappear = "packageDisappear",
            .value_person = "person",
            .value_personDisappear = "personDisappear",
            .value_vehicle = "vehicle",
            .value_vehicleDisappear = "vehicleDisappear",
            .value_pet = "pet",
            .value_petDisappear = "petDisappear",
            .value_loitering = "loitering",
            .value_loiteringDisappear = "loiteringDisappear",
            .value_gestureV = "gestureV",
            .value_gestureFour = "gestureFour",
            .value_gestureFive = "gestureFive",
            .value_gestureGun = "gestureGun",
            .value_gestureOk = "gestureOk",
            .value_lensObstruction = "lensObstruction",
        },
    .attr_supportedEvents =
        {
            .name = "supportedEvents",
            .property = ATTR_SET_VALUE_ARRAY,
            .valueType = VALUE_TYPE_STRING,
            .values = {"package", "packageDisappear", "person", "personDisappear", "vehicle", "vehicleDisappear", "pet",
                       "petDisappear", "loitering", "loiteringDisappear", "gestureV", "gestureFour", "gestureFive",
                       "gestureGun", "gestureOk", "lensObstruction"},
            .value_package = "package",
            .value_packageDisappear = "packageDisappear",
            .value_person = "person",
            .value_personDisappear = "personDisappear",
            .value_vehicle = "vehicle",
            .value_vehicleDisappear = "vehicleDisappear",
            .value_pet = "pet",
            .value_petDisappear = "petDisappear",
            .value_loitering = "loitering",
            .value_loiteringDisappear = "loiteringDisappear",
            .value_gestureV = "gestureV",
            .value_gestureFour = "gestureFour",
            .value_gestureFive = "gestureFive",
            .value_gestureGun = "gestureGun",
            .value_gestureOk = "gestureOk",
            .value_lensObstruction = "lensObstruction",
        },
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_CAMERA_EVENT_ */

/* ***************************************************************************
 *
 * Copyright 2022 Samsung Electronics All Rights Reserved.
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

#ifndef _BLUEZ_GDBUS_UTIL_H_
#define _BLUEZ_GDBUS_UTIL_H_

#include <gio/gio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BLUEZ_SERVICE_NAME "org.bluez"

#define DBUS_PROP_IFACE "org.freedesktop.DBus.Properties"
#define DBUS_OM_IFACE "org.freedesktop.DBus.ObjectManager"

#define ADAPTER_IFACE "org.bluez.Adapter1"
#define LE_ADVERTISEMENT_IFACE "org.bluez.LEAdvertisement1"
#define LE_ADVERTISING_MANAGER_IFACE "org.bluez.LEAdvertisingManager1"

#define HCI_OBJECT_PATH "/org/bluez/hci0"
#define ADVERTISEMENT_PATH "/org/bluez/advertisement/discovery"

#define GATT_MNGR_INTERFACE "org.bluez.GattManager1"
#define GATT_SERV_INTERFACE "org.bluez.GattService1"
#define GATT_CHAR_INTERFACE "org.bluez.GattCharacteristic1"
#define GATT_DESC_INTERFACE "org.bluez.GattDescriptor1"

#define SERVICE_PATH "/org/bluez/example/service0"
#define CHAR_PATH "/org/bluez/example/service0/char0"
#define DESC_PATH "/org/bluez/example/service0/char0/desc0"

#define BLUEZ_DEVICE_IFACE "org.bluez.Device1"

    char *find_bluez_adapter(void);
    void bluez_gdbus_call_async_cb(GObject *source_object, GAsyncResult *res, gpointer user_data);

#ifdef __cplusplus
}
#endif

#endif /* _BLUEZ_GDBUS_UTIL_H_ */

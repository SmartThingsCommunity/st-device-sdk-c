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

#include "bluez_device.h"

#include <gio/gio.h>
#include <stdbool.h>

#include "bluez_gdbus_util.h"
#include "../gdbus/gdbus_util.h"
#include "iot_bsp_ble.h"

extern iot_ble_cbs_t *g_ble_cbs;

static bool is_connected;
static char *connected_device;

static void bluez_signal_device_changed(GDBusConnection *conn,
                                        const gchar *sender,
                                        const gchar *path,
                                        const gchar *interface,
                                        const gchar *signal,
                                        GVariant *params,
                                        void *userdata)
{
    (void)conn;
    (void)sender;
    (void)path;
    (void)interface;
    (void)userdata;

    GVariantIter *properties = NULL;
    GVariantIter *unknown = NULL;
    const char *iface;
    const char *key;
    GVariant *value = NULL;
    const gchar *signature = g_variant_get_type_string(params);
    int ret;
    GVariant *reply;

    if (strcmp(signature, "(sa{sv}as)") != 0)
    {
        g_print("Invalid signature for %s: %s != %s", signal, signature, "(sa{sv}as)");
        goto done;
    }

    g_variant_get(params, "(&sa{sv}as)", &iface, &properties, &unknown);
    while (g_variant_iter_next(properties, "{&sv}", &key, &value))
    {
        if (!g_strcmp0(key, "Connected"))
        {
            if (!g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
            {
                g_print("Invalid argument type for %s: %s != %s", key,
                        g_variant_get_type_string(value), "b");
                goto done;
            }
            if (is_connected && strcmp(connected_device, path))
            {
                if (g_variant_get_boolean(value))
                {
                    ret = gdbus_method_call_sync((char *)BLUEZ_SERVICE_NAME,
                                                 (char *)path,
                                                 (char *)BLUEZ_DEVICE_IFACE,
                                                 (char *)"Disconnect",
                                                 NULL,
                                                 &reply);
                    if (ret)
                    {
                        g_print("error while sending get interface method call %d\n", ret);
                    }
                    g_print("New device connected but decline\n");
                }
                return;
            }
            is_connected = g_variant_get_boolean(value);
            if (connected_device)
                free(connected_device);
            connected_device = strdup(path);
            g_print("Device(%s) is \"%s\"\n", path, g_variant_get_boolean(value) ? "Connected" : "Disconnected");
            if (g_variant_get_boolean(value) && g_ble_cbs && g_ble_cbs->conn_cb)
            {
                g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
            }
            else if (!g_variant_get_boolean(value) && g_ble_cbs && g_ble_cbs->conn_cb)
            {
                g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
            }
        }
    }
done:
    if (properties != NULL)
        g_variant_iter_free(properties);
    if (value != NULL)
        g_variant_unref(value);
}

static void bluez_signal_device_added(GDBusConnection *conn,
                                      const gchar *sender,
                                      const gchar *path,
                                      const gchar *interface,
                                      const gchar *signal,
                                      GVariant *params,
                                      void *userdata)
{
    (void)conn;
    (void)sender;
    (void)path;
    (void)interface;
    (void)userdata;

    GVariantIter *interfaces_and_properties = NULL;
    GVariantIter *properties = NULL;
    const char *iface;
    gchar *object;
    const char *key;
    GVariant *value = NULL;
    const gchar *signature = g_variant_get_type_string(params);
    int ret;
    GVariant *reply;

    if (strcmp(signature, "(oa{sa{sv}})") != 0)
    {
        g_print("Invalid signature for %s: %s != %s", signal, signature, "(sa{sv}as)");
        return;
    }

    g_variant_get(params, "(&oa{sa{sv}})", &object, &interfaces_and_properties);
    if (!strncmp(object, HCI_OBJECT_PATH, strlen(HCI_OBJECT_PATH)))
    {
        while (g_variant_iter_next(interfaces_and_properties, "{&sa{sv}}", &iface, &properties))
        {
            if (!g_strcmp0(iface, BLUEZ_DEVICE_IFACE))
            {
                while (g_variant_iter_next(properties, "{&sv}", &key, &value))
                {
                    if (!g_strcmp0(key, "Connected"))
                    {
                        if (!g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
                        {
                            g_print("Invalid argument type for %s: %s != %s", key,
                                    g_variant_get_type_string(value), "b");
                            return;
                        }
                        if (is_connected && strcmp(connected_device, object))
                        {
                            if (g_variant_get_boolean(value))
                            {
                                ret = gdbus_method_call_sync((char *)BLUEZ_SERVICE_NAME,
                                                             (char *)object,
                                                             (char *)BLUEZ_DEVICE_IFACE,
                                                             (char *)"Disconnect",
                                                             NULL,
                                                             &reply);
                                if (ret)
                                {
                                    g_print("error while sending get interface method call %d\n", ret);
                                }
                                g_print("New device connected but decline\n");
                            }
                            return;
                        }
                        is_connected = g_variant_get_boolean(value);
                        if (connected_device)
                            free(connected_device);
                        connected_device = strdup(object);
                        g_print("Device(%s) is \"%s\"\n", object, g_variant_get_boolean(value) ? "Connected" : "Disconnected");
                        if (g_variant_get_boolean(value) && g_ble_cbs && g_ble_cbs->conn_cb)
                        {
                            g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_CONNECTED);
                        }
                        else if (!g_variant_get_boolean(value) && g_ble_cbs && g_ble_cbs->conn_cb)
                        {
                            g_ble_cbs->conn_cb(IOT_BLE_CONNECTION_EVENT_DISCONNECTED);
                        }
                    }
                }
            }
        }
    }
}

void init_bluez_device(void)
{
    GDBusConnection *system_gconn = NULL;

    system_gconn = get_gdbus_connection();
    g_dbus_connection_signal_subscribe(system_gconn,
                                       BLUEZ_SERVICE_NAME,
                                       DBUS_PROP_IFACE,
                                       "PropertiesChanged",
                                       NULL,
                                       BLUEZ_DEVICE_IFACE,
                                       G_DBUS_SIGNAL_FLAGS_NONE,
                                       bluez_signal_device_changed,
                                       NULL,
                                       NULL);

    g_dbus_connection_signal_subscribe(system_gconn,
                                       BLUEZ_SERVICE_NAME,
                                       DBUS_OM_IFACE,
                                       "InterfacesAdded",
                                       NULL,
                                       NULL,
                                       G_DBUS_SIGNAL_FLAGS_NONE,
                                       bluez_signal_device_added,
                                       NULL,
                                       NULL);
}

void deinit_bluez_device(void)
{
}

void disconnect_bluez_device()
{
    int ret;
    GVariant *reply;

    if (is_connected)
    {
        ret = gdbus_method_call_sync((char *)BLUEZ_SERVICE_NAME,
                                     (char *)connected_device,
                                     (char *)BLUEZ_DEVICE_IFACE,
                                     (char *)"Disconnect",
                                     NULL,
                                     &reply);
        if (ret)
        {
            g_print("error while sending disconnect method call %d\n", ret);
        }
        else
        {
            g_print("Disconnect %s\n", connected_device);
        }
    }
}

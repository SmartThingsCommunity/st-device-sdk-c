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

#include "bluez_gdbus_util.h"

#include <gio/gio.h>
#include <glib.h>

#include "iot_debug.h"
#include "../gdbus/gdbus_util.h"

static char *_extract_bluez_adapter_path(GVariantIter *iter)
{
    char *object_path = NULL;
    GVariantIter *interface_iter;
    GVariantIter *svc_iter;
    char *interface_str = NULL, *last_str = NULL;
    GVariant *last_variant;

    /* Parse the signature: oa{sa{sv}}} */
    while (g_variant_iter_loop(iter, "{&oa{sa{sv}}}", &object_path,
                               &interface_iter))
    {

        if (object_path == NULL)
            continue;

        IOT_DEBUG("Object Path: %s", object_path);
        while (g_variant_iter_loop(interface_iter, "{&sa{sv}}",
                                   &interface_str, &svc_iter))
        {

            if (g_strcmp0(interface_str, LE_ADVERTISING_MANAGER_IFACE) != 0)
                continue;

            IOT_DEBUG("Object Path: %s", object_path);
            g_variant_iter_free(svc_iter);
            g_variant_iter_free(interface_iter);
            return g_strdup(object_path);
        }
    }
    return NULL;
}

char *find_bluez_adapter(void)
{
    int ret;
    GVariant *reply, *prop;
    GVariantIter *iter;
    char *key;
    GVariant *value;
    char *adapter_path = NULL;

    ret = gdbus_method_call_sync((char *)BLUEZ_SERVICE_NAME,
                                 (char *)"/",
                                 (char *)DBUS_OM_IFACE,
                                 (char *)"GetManagedObjects",
                                 NULL,
                                 &reply);
    if (ret)
    {
        IOT_ERROR("error while sending get interface method call %d", ret);
        return NULL;
    }

    IOT_DEBUG("TYPE %s", g_variant_get_type_string(reply));

    g_variant_get(reply, "(a{oa{sa{sv}}})", &iter);
    adapter_path = _extract_bluez_adapter_path(iter);
    IOT_DEBUG("adapter_path %s", adapter_path);

    return adapter_path;
}

void bluez_gdbus_call_async_cb(GObject *source_object,
                               GAsyncResult *res, gpointer user_data)
{
    IOT_DEBUG("bluez_gdbus_util: Enter in bluez_gdbus_call_async_cb");
    GError *error = NULL;
    GDBusConnection *system_gconn = NULL;
    GVariant *value;

    system_gconn = get_gdbus_connection();
    value = g_dbus_connection_call_finish(system_gconn, res, &error);

    if (error)
    {
        IOT_ERROR("Error : %s", error->message);
        g_clear_error(&error);
        return;
    }

    IOT_DEBUG("gdbus async method call Success %s", (user_data) ? (const gchar *)user_data : "");
    g_variant_unref(value);
}

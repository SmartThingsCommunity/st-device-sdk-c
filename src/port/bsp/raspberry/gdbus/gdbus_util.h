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

#ifndef _GDBUS_UTIL_H_
#define _GDBUS_UTIL_H_

#include <gio/gio.h>
#include <glib.h>

#ifdef __cplusplus
extern "C"
{
#endif

GDBusConnection *get_gdbus_connection(void);

int gdbus_init_loop();

int gdbus_method_call_sync(char *service, char *object_path, char *iface,
				   char *method, GVariant *parameter, GVariant **reply);

int gdbus_method_call_async(char *service, char *object_path,
				char *iface, char *method, GVariant *parameter,
				GAsyncReadyCallback asyncCB, gpointer cdData);

guint gdbus_register_object(const char *path, const gchar *xml, GDBusInterfaceVTable vtable);

#ifdef __cplusplus
}
#endif

#endif

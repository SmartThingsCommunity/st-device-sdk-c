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

#include <stdio.h>
#include <stdbool.h>
#include <gio/gio.h>
#include <glib.h>
#include <errno.h>
#include <pthread.h>

#include "gdbus_util.h"
#include "iot_debug.h"

static GDBusConnection *g_connection;
static pthread_t* g_loop_thread;

GDBusConnection *get_gdbus_connection(void)
{
	IOT_DEBUG("gdbus_util: Enter in get_gdbus_connection");
	if (!g_connection)
	{
		g_autoptr(GError) error = NULL;
		g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error)
		{
			IOT_ERROR("failed to get gdbus connection %s", error->message);
			g_clear_error(&error);
			return NULL;
		}
	}

	return g_connection;
}

static void *gdbus_loop_thread(void *arg)
{
	GMainLoop* main_loop;

	main_loop = g_main_loop_new (NULL, 0);
	g_main_loop_run(main_loop);
}

int gdbus_init_loop()
{
	pthread_attr_t attr;

	if (g_loop_thread != NULL) {
		printf("already running gdbus loop\n");
		return 0;
	}

	g_loop_thread = malloc(sizeof(pthread_t));
	if (g_loop_thread == NULL)
		return -1;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(g_loop_thread, &attr, gdbus_loop_thread, NULL);
	pthread_attr_destroy(&attr);

	return 0;
}

int gdbus_method_call_sync(char *service, char *object_path, char *iface,
						   char *method, GVariant *parameter, GVariant **reply)
{
	int ret;
	g_autoptr(GError) error = NULL;

	if (!get_gdbus_connection())
		return -EINVAL;

	*reply = g_dbus_connection_call_sync(get_gdbus_connection(), service,
										 object_path, iface, method, parameter, NULL, G_DBUS_CALL_FLAGS_NONE,
										 G_MAXINT, NULL, &error);
	if (error)
	{
		IOT_ERROR("Error while sending dbus method call %s", error->message);
		ret = error->code;
		g_clear_error(&error);
		return ret;
	}
	return 0;
}

int gdbus_method_call_async(char *service, char *object_path,
							char *iface, char *method, GVariant *parameter,
							GAsyncReadyCallback asyncCB, gpointer cdData)
{
	guint timeout_msec = 5000;
	g_dbus_connection_call(get_gdbus_connection(), service, object_path, iface,
						   method, parameter, NULL, G_DBUS_CALL_FLAGS_NONE, timeout_msec, NULL,
						   (GAsyncReadyCallback)asyncCB, cdData);

	return 0;
}

guint gdbus_register_object(const char *path, const gchar *xml, GDBusInterfaceVTable vtable)
{
	guint registration_id = 0;
	GDBusNodeInfo *introspection_data = NULL;

	introspection_data = g_dbus_node_info_new_for_xml(xml, NULL);
	g_assert(introspection_data != NULL);

	IOT_DEBUG("Registering gdbus object");
	IOT_DEBUG("Path: %s", path);
	IOT_DEBUG("Interface: %s", introspection_data->interfaces[0]->name);

	registration_id = g_dbus_connection_register_object(get_gdbus_connection(),
														path,
														introspection_data->interfaces[0],
														&vtable,
														NULL,  /* user_data */
														NULL,  /* user_data_free_func */
														NULL); /* GError** */

	//g_dbus_node_info_unref(introspection_data);
	g_assert(registration_id > 0);

	return registration_id;
}

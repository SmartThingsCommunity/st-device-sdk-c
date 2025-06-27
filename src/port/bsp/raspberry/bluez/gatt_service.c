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
#include "gatt_service.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gio/gio.h>

#include "bluez_gdbus_util.h"
#include "iot_debug.h"
#include "../gdbus/gdbus_util.h"

#define MAX_DATA_LEN 1024

typedef struct
{
	char *path;
	char *uuid;

	gchar *xml;
	GDBusInterfaceVTable vtable;
	guint registration_id;
} descriptor;

typedef struct
{
	char *path;
	char *uuid;
	descriptor *desc0;

	gchar *xml;
	GDBusInterfaceVTable vtable;
	guint registration_id;
} characteristic;

typedef struct
{
	char *path;
	char *uuid;
	gboolean primary;
	characteristic *char0;

	gchar *xml;
	GDBusInterfaceVTable vtable;
	guint registration_id;
} service;

typedef struct
{
	char *path;
	char *name;
	service *serv;

	gchar *xml;
	GDBusInterfaceVTable vtable;
	guint registration_id;
} application;

static application app;
static service app_service;

uint16_t g_mtu;

extern iot_ble_cbs_t *g_ble_cbs;

/* Introspection data for the service we are exporting */
static const gchar app_xml[] =
	"<node>"
	"  <interface name='org.freedesktop.DBus.ObjectManager'>"
	"    <method name='GetManagedObjects'>"
	"      <arg type='a{oa{sa{sv}}}' name='objects' direction='out'/>"
	"    </method>"
	"  </interface>"
	"</node>";

static const gchar service_xml[] =
	"<node>"
	"  <interface name='org.bluez.GattService1'>"
	"    <property type='s' name='UUID' access='read'/>"
	"    <property type='b' name='Primary' access='read'/>"
	//  "    <property type='ao' name='Characteristics' access='read'/>"
	"  </interface>"
	"</node>";

static const gchar char_xml[] =
	"<node>"
	"  <interface name='org.bluez.GattCharacteristic1'>"
	"    <method name='ReadValue'>"
	"      <arg type='a{sv}' name='options' direction='in'/>"
	"      <arg type='ay' name='value' direction='out'/>"
	"    </method>"
	"    <method name='WriteValue'>"
	"      <arg type='ay' name='value' direction='in'/>"
	"      <arg type='a{sv}' name='options' direction='in'/>"
	"    </method>"
	"    <method name='StartNotify' />"
	"    <method name='StopNotify' />"
	"    <property type='s' name='UUID' access='read'/>"
	"    <property type='o' name='Service' access='read'/>"
	"    <property type='as' name='Flags' access='read'/>"
	"  </interface>"
	"</node>";

/*static const gchar desc_xml[] =
	"<node>"
	"  <interface name='org.bluez.GattDescriptor1'>"
	"    <method name='ReadValue'>"
	"      <arg type='a{sv}' name='options' direction='in'/>"
	"      <arg type='ay' name='value' direction='out'/>"
	"    </method>"
	"    <method name='WriteValue'>"
	"      <arg type='ay' name='value' direction='in'/>"
	"      <arg type='a{sv}' name='options' direction='in'/>"
	"    </method>"
	"    <property type='s' name='UUID' access='read'/>"
	"    <property type='o' name='Characteristic' access='read'/>"
	"    <property type='as' name='Flags' access='read'/>"
	"  </interface>"
	"</node>";*/
/* ---------------------------------------------------------------------------------------------------- */

#define SERVICE_UUID "FD1D"
#define CHAR_UUID "BE940F0E-AE2D-4F8E-A4C7-300280E60E09"
#define DESC_UUID "2902"

static void gatt_build_service(GVariantBuilder *managedBuilder)
{
	GVariantBuilder *svc_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
	GVariantBuilder *inner_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(inner_builder, "{sv}", "UUID",
						  g_variant_new_string(SERVICE_UUID));
	g_variant_builder_add(inner_builder, "{sv}", "Primary",
						  g_variant_new_boolean(TRUE));

	GVariantBuilder *inner_builder1 = g_variant_builder_new(G_VARIANT_TYPE("ao"));

	IOT_DEBUG("Adding Charatarisitcs list");
	g_variant_builder_add(inner_builder1, "o", CHAR_PATH);

	IOT_DEBUG("Collate");
	GVariant *svc_char = g_variant_new("ao", inner_builder1);
	g_variant_builder_add(inner_builder, "{sv}", "Characteristics", svc_char);
	g_variant_builder_add(svc_builder, "{sa{sv}}", GATT_SERV_INTERFACE, inner_builder);
	g_variant_builder_add(managedBuilder, "{oa{sa{sv}}}", SERVICE_PATH, svc_builder);
	g_variant_builder_unref(inner_builder1);
}

static void gatt_build_char(GVariantBuilder *managedBuilder)
{
	GVariantBuilder *char_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
	GVariantBuilder *inner_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(inner_builder, "{sv}", "Service",
						  g_variant_new("o", SERVICE_PATH));
	g_variant_builder_add(inner_builder, "{sv}", "UUID",
						  g_variant_new_string(CHAR_UUID));

	// Add flags
	GVariantBuilder *flag_builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

	IOT_DEBUG("Adding Flag list");
	//g_variant_builder_add(flag_builder, "s", "read");
	g_variant_builder_add(flag_builder, "s", "write");
	g_variant_builder_add(flag_builder, "s", "notify");
	g_variant_builder_add(flag_builder, "s", "indicate");

	// Add Descriptors
	//GVariantBuilder *desc_builder = g_variant_builder_new(G_VARIANT_TYPE("ao"));

	//IOT_DEBUG("Adding Descriptor list");
	//g_variant_builder_add(desc_builder, "o", DESC_PATH);

	// Collate all
	IOT_DEBUG("Collate");
	GVariant *char_flag = g_variant_new("as", flag_builder);
	g_variant_builder_add(inner_builder, "{sv}", "Flags", char_flag);

	//GVariant *char_desc = g_variant_new("ao", desc_builder);
	//g_variant_builder_add(inner_builder, "{sv}", "Descriptors", char_desc);

	g_variant_builder_add(char_builder, "{sa{sv}}", GATT_CHAR_INTERFACE, inner_builder);
	g_variant_builder_add(managedBuilder, "{oa{sa{sv}}}", CHAR_PATH, char_builder);
	//g_variant_builder_unref(flag_builder);
	//g_variant_builder_unref(desc_builder);
}

static void gatt_build_desc(GVariantBuilder *managedBuilder)
{
	GVariantBuilder *descriptor_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
	GVariantBuilder *inner_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(inner_builder, "{sv}", "Characteristic",
						  g_variant_new("o", CHAR_PATH));
	g_variant_builder_add(inner_builder, "{sv}", "UUID",
						  g_variant_new_string(DESC_UUID));

	// Add flags
	GVariantBuilder *flag_builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

	IOT_DEBUG("Adding Flag list");
	g_variant_builder_add(flag_builder, "s", "read");

	// Collate all
	IOT_DEBUG("Collate");
	GVariant *char_flag = g_variant_new("as", flag_builder);
	g_variant_builder_add(inner_builder, "{sv}", "Flags", char_flag);

	//g_variant_builder_add(descriptor_builder, "{sa{sv}}", GATT_DESC_INTERFACE, inner_builder);
	//g_variant_builder_add(managedBuilder, "{oa{sa{sv}}}", DESC_PATH, descriptor_builder);
	g_variant_builder_unref(flag_builder);
}

static void gatt_build_managed_objects(GVariantBuilder *managedBuilder)
{
	gatt_build_service(managedBuilder);
	gatt_build_char(managedBuilder);
	gatt_build_desc(managedBuilder);

	IOT_DEBUG("Build Successfully");
}

static void
handle_app_method_call(GDBusConnection *connection,
					   const gchar *sender,
					   const gchar *object_path,
					   const gchar *interface_name,
					   const gchar *method_name,
					   GVariant *parameters,
					   GDBusMethodInvocation *invocation,
					   gpointer user_data)
{
	if (g_strcmp0(method_name, "GetManagedObjects") == 0)
	{
		IOT_DEBUG("Method: GetManagedObjects");
		GVariantBuilder *builder = NULL;

		builder = g_variant_builder_new(G_VARIANT_TYPE("a{oa{sa{sv}}}"));
		gatt_build_managed_objects(builder);

		g_dbus_method_invocation_return_value(invocation,
											  g_variant_new("(a{oa{sa{sv}}})", builder));
		g_variant_builder_unref(builder);
	}
	else
	{
		IOT_DEBUG("Method: None");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.NotOnUnix",
												   "Your OS does not support file descriptor passing");
	}
}

/* Handle Service */
static void
handle_service_method_call(GDBusConnection *connection,
						   const gchar *sender,
						   const gchar *object_path,
						   const gchar *interface_name,
						   const gchar *method_name,
						   GVariant *parameters,
						   GDBusMethodInvocation *invocation,
						   gpointer user_data)
{
	IOT_DEBUG("Method: Not Supported");
	g_dbus_method_invocation_return_dbus_error(invocation,
											   "org.gtk.GDBus.NotOnUnix",
											   "Your OS does not support file descriptor passing");
}

static GVariant *
handle_service_get_property(GDBusConnection *connection,
							const gchar *sender,
							const gchar *object_path,
							const gchar *interface_name,
							const gchar *property_name,
							GError **error,
							gpointer user_data)
{
	GVariant *ret;

	ret = NULL;
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("s", app_service.uuid);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "Primary") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("b", TRUE);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	return ret;
}

static gboolean
handle_service_set_property(GDBusConnection *connection,
							const gchar *sender,
							const gchar *object_path,
							const gchar *interface_name,
							const gchar *property_name,
							GVariant *value,
							GError **error,
							gpointer user_data)
{
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "Primary") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else
	{
		IOT_DEBUG("SetProperty: None");
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
					"Hello AGAIN %s. I thought I said writing this property "
					"always results in an error. kthxbye",
					sender);
	}

	return *error == NULL;
}

/* Handle Characteristic  */
static void
handle_char_method_call(GDBusConnection *connection,
						const gchar *sender,
						const gchar *object_path,
						const gchar *interface_name,
						const gchar *method_name,
						GVariant *parameters,
						GDBusMethodInvocation *invocation,
						gpointer user_data)
{
	if (g_strcmp0(method_name, "ReadValue") == 0)
	{
		IOT_DEBUG("Method: ReadValue");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.NotSupported",
												   "Read Not Supported");
	}
	else if (g_strcmp0(method_name, "WriteValue") == 0)
	{
		GVariantIter *iter;
		GVariantIter *iter_options;
		char *option;
		GVariant *value;
		uint16_t mtu;
		uint8_t val;
		uint8_t data[MAX_DATA_LEN] = {0};
		uint32_t data_len;
		char *device = NULL;

		IOT_DEBUG("Method: WriteValue");
		g_variant_get(parameters, "(aya{sv})", &iter, &iter_options);

		while (g_variant_iter_loop(iter_options, "{sv}", &option, &value))
		{
			IOT_DEBUG("Option: %s", option);
			IOT_DEBUG("Property Type: %s", g_variant_get_type_string(value));

			if (g_strcmp0(option, "device") == 0)
			{
				g_variant_get(value, "o", &device);
				IOT_DEBUG("Option Value: %s", device);
			}
			if (g_strcmp0(option, "mtu") == 0)
			{
				g_variant_get(value, "q", &mtu);
				IOT_DEBUG("Option Value: %d", mtu);
				g_mtu = mtu;
			}
		}

		for (data_len = 0; g_variant_iter_loop(iter, "y", &val); data_len++)
		{
			data[data_len] = val;
			IOT_DEBUG("received data[%d] : %02x", data_len, data[data_len]);
		}
		g_dbus_method_invocation_return_value(invocation, NULL);
		if (g_ble_cbs && g_ble_cbs->write_cb)
		{
			g_ble_cbs->write_cb(data, data_len);
		}
	}
	else if (g_strcmp0(method_name, "StartNotify") == 0)
	{
		IOT_DEBUG("StartNotify");
		// TODO: Implement
	}
	else if (g_strcmp0(method_name, "StopNotify") == 0)
	{
		IOT_DEBUG("StopNotify");
		// TODO: Implement
	}
	else if (g_strcmp0(method_name, "Confirm") == 0)
	{
		IOT_DEBUG("Confirm");
		// TODO: Implement
	}
	else
	{
		IOT_DEBUG("Method: None");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.NotSupported",
												   "Method Not Supported");
	}
}

static GVariant *
handle_char_get_property(GDBusConnection *connection,
						 const gchar *sender,
						 const gchar *object_path,
						 const gchar *interface_name,
						 const gchar *property_name,
						 GError **error,
						 gpointer user_data)
{
	GVariant *ret = NULL;

	ret = NULL;
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("s", app_service.char0->uuid);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "Service") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("o", app_service.path);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "Flags") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		GVariantBuilder *builder;

		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		g_variant_builder_add(builder, "s", "write");
		g_variant_builder_add(builder, "s", "notify");
		//g_variant_builder_add(builder, "s", "indicate");


		ret = g_variant_new("as", builder); // Check if works
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
		g_variant_builder_unref(builder);
	}
	else if (g_strcmp0(property_name, "MTU") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("q", g_mtu);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}

	return ret;
}

static gboolean
handle_char_set_property(GDBusConnection *connection,
						 const gchar *sender,
						 const gchar *object_path,
						 const gchar *interface_name,
						 const gchar *property_name,
						 GVariant *value,
						 GError **error,
						 gpointer user_data)
{
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "Service") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "Flags") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else
	{
		IOT_DEBUG("Property Name: %s", "None");
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}

	return *error == NULL;
}

/* Handle send descriptor */
/*static void
handle_desc_method_call(GDBusConnection *connection,
						const gchar *sender,
						const gchar *object_path,
						const gchar *interface_name,
						const gchar *method_name,
						GVariant *parameters,
						GDBusMethodInvocation *invocation,
						gpointer user_data)
{
	if (g_strcmp0(method_name, "ReadValue") == 0)
	{
		IOT_DEBUG("Method: ReadValue");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.OnlyWrite",
												   "Read Not Supported");
	}
	else if (g_strcmp0(method_name, "WriteValue") == 0)
	{
		IOT_DEBUG("Method: WriteValue");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.OnlyWrite",
												   "Write Not Supported");
	}
	else
	{
		IOT_DEBUG("Method: None");
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.NotSupported",
												   "Method Not Supported");
	}
}

static GVariant *
handle_desc_get_property(GDBusConnection *connection,
						 const gchar *sender,
						 const gchar *object_path,
						 const gchar *interface_name,
						 const gchar *property_name,
						 GError **error,
						 gpointer user_data)
{
	GVariant *ret = NULL;

	ret = NULL;
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("s", app_service.char0->desc0->uuid);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "Characteristic") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		ret = g_variant_new("o", app_service.char0->path);
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "Flags") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		GVariantBuilder *builder;

		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		// g_variant_builder_add(builder, "s", "write-without-response");
		// TODO: Nothing supported for now

		ret = g_variant_new("(as)", builder); // Check if works
		IOT_DEBUG("Property Type: %s", g_variant_get_type_string(ret));
		g_variant_builder_unref(builder);
	}

	return ret;
}

static gboolean
handle_desc_set_property(GDBusConnection *connection,
						 const gchar *sender,
						 const gchar *object_path,
						 const gchar *interface_name,
						 const gchar *property_name,
						 GVariant *value,
						 GError **error,
						 gpointer user_data)
{
	if (g_strcmp0(property_name, "UUID") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "Service") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "Flags") == 0)
	{
		IOT_DEBUG("Property Name: %s", property_name);
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else
	{
		IOT_DEBUG("Property Name: %s", "None");
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}

	return *error == NULL;
}*/

/* for now */
static const GDBusInterfaceVTable app_vtable =
	{
		handle_app_method_call,
		NULL,
		NULL};

static const GDBusInterfaceVTable service_vtable =
	{
		handle_service_method_call,
		handle_service_get_property,
		handle_service_set_property};

static const GDBusInterfaceVTable char_vtable =
	{
		handle_char_method_call,
		handle_char_get_property,
		handle_char_set_property};

/*static const GDBusInterfaceVTable desc_vtable =
	{
		handle_desc_method_call,
		handle_desc_get_property,
		handle_desc_set_property};*/

static void init_service_data(char *app_path)
{
	characteristic *c0;
	//descriptor *c0d0;
	char *path = g_strdup_printf("%s/service%d", app_path, 0);

	//c0d0 = (descriptor *)g_malloc0(sizeof(descriptor));
	//c0d0->path = g_strdup_printf("%s/char%d/desc%d", path, 0, 0);
	//c0d0->uuid = (char *)"DESC-C0D0";
	//c0d0->xml = (char *)desc_xml;
	//c0d0->vtable = desc_vtable;

	c0 = (characteristic *)g_malloc0(sizeof(characteristic));
	c0->path = g_strdup_printf("%s/char%d", path, 0);
	c0->uuid = (char *)"CHAR-C0";
	//c0->desc0 = c0d0;
	c0->xml = (char *)char_xml;
	c0->vtable = char_vtable;

	app_service.path = g_strdup(path);
	app_service.uuid = (char *)"SERV-BLE";
	app_service.primary = TRUE;
	app_service.char0 = c0;
	app_service.xml = (char *)service_xml;
	app_service.vtable = service_vtable;

	app.name = (char *)"Ble-Onboarding";
	app.path = g_strdup(app_path);
	app.serv = &app_service;
	app.xml = (char *)app_xml;
	app.vtable = app_vtable;
}

/* ---------------------------------------------------------------------------------------------------- */

void send_data_over_gatt(uint8_t *data, uint32_t len)
{
	int ret;
	int i;
	GVariantBuilder *outer_builder;
	GVariantBuilder *inner_builder;
	GVariantBuilder *invalidated_builder;
	GVariant *update_value = NULL;
	GError *error = NULL;
	IOT_DEBUG("Updating characteristic value");

	outer_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	invalidated_builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

	inner_builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	for (i = 0; i < len; i++)
		g_variant_builder_add(inner_builder, "y", data[i]);

	update_value = g_variant_new("ay", inner_builder);

	g_variant_builder_add(outer_builder, "{sv}", "Value",
						  update_value);

	IOT_DEBUG("PATH: %s", app_service.char0->path);
	ret = g_dbus_connection_emit_signal(get_gdbus_connection(), NULL,
										app_service.char0->path,
										"org.freedesktop.DBus.Properties",
										"PropertiesChanged",
										g_variant_new("(sa{sv}as)",
													  "org.bluez.GattCharacteristic1",
													  outer_builder, invalidated_builder),
										&error);

	if (!ret)
	{
		IOT_ERROR("D-Bus API");
		if (error != NULL)
		{
			IOT_ERROR("D-Bus API failure: errCode[%x], \
						message[%s]",
					  error->code, error->message);
			g_clear_error(&error);
		}
	}
}

uint16_t get_mtu(void)
{
	return g_mtu;
}

void set_mtu(uint16_t mtu)
{
	g_mtu = mtu;
}

void start_gatt_service(void)
{
	char *path = (char *)"/org/bluez/example";

	IOT_DEBUG("Application Path %s", path);

	init_service_data(path);
	app.registration_id = gdbus_register_object(app.path, app.xml, app.vtable);
	app_service.registration_id = gdbus_register_object(app_service.path, app_service.xml, app_service.vtable);
	app_service.char0->registration_id = gdbus_register_object(app_service.char0->path, app_service.char0->xml, app_service.char0->vtable);
	//app_service.char0->desc0->registration_id = gdbus_register_object(app_service.char0->desc0->path, app_service.char0->desc0->xml, app_service.char0->desc0->vtable);
}

void stop_gatt_service(void)
{
	//g_dbus_connection_unregister_object(get_gdbus_connection(), app_service.char0->desc0->registration_id);
	g_dbus_connection_unregister_object(get_gdbus_connection(), app_service.char0->registration_id);
	g_dbus_connection_unregister_object(get_gdbus_connection(), app_service.registration_id);
	g_dbus_connection_unregister_object(get_gdbus_connection(), app.registration_id);
}

void register_gatt_application(void)
{
	char *adapter_path = NULL;

	adapter_path = find_bluez_adapter();

	gdbus_method_call_async((char *)BLUEZ_SERVICE_NAME,
							(char *)adapter_path,
							(char *)GATT_MNGR_INTERFACE,
							(char *)"RegisterApplication",
							g_variant_new("(oa{sv})", "/org/bluez/example", NULL),
							bluez_gdbus_call_async_cb,
							(gpointer) "RegisterApplication");

	g_free(adapter_path);
}

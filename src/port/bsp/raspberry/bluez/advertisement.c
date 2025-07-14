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

#include "advertisement.h"

#include <gio/gio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "bluez_gdbus_util.h"
#include "iot_debug.h"
#include "iot_os_util.h"
#include "../gdbus/gdbus_util.h"

#define MAC_STR_LEN 17
#define PACKET_MAX_LEN 31
#define MFDATA_PACKET_MAX_LEN 24

static uint16_t g_manufacturer_code;
static size_t g_manufacturer_data_len;
static uint8_t g_manufacturer_data[31]; /* BLE AD Type : 0xFF */
static char g_local_name[31];			/* BLE AD Type : 0x09 */

static guint registration_id;

/* Introspection data for the service we are exporting */
static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.LEAdvertisement1'>"
	"    <method name='Release' />"
	"    <property type='s' name='Type' access='readwrite'/>"
	"    <property type='a{qv}' name='ManufacturerData' access='readwrite'/>"
	"    <property type='a{qv}' name='ManufacturerDataSR' access='readwrite'/>"
	"    <property type='s' name='LocalName' access='readwrite'/>"
	"  </interface>"
	"</node>";

/* ---------------------------------------------------------------------------------------------------- */

static void
handle_method_call(GDBusConnection *connection,
				   const gchar *sender,
				   const gchar *object_path,
				   const gchar *interface_name,
				   const gchar *method_name,
				   GVariant *parameters,
				   GDBusMethodInvocation *invocation,
				   gpointer user_data)
{
	IOT_DEBUG("Method Name: %s", method_name);
	if (g_strcmp0(method_name, "Release") == 0)
	{
		g_dbus_method_invocation_return_value(invocation, NULL);
	}
	else
	{
		g_dbus_method_invocation_return_dbus_error(invocation,
												   "org.gtk.GDBus.NotOnUnix",
												   "Your OS does not support file descriptor passing");
	}
}

static GVariant *
handle_get_property(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *property_name,
					GError **error,
					gpointer user_data)
{
	GVariant *ret = NULL;

	IOT_DEBUG("Property Name: %s", property_name);
	if (g_strcmp0(property_name, "Type") == 0)
	{
		ret = g_variant_new("s", "peripheral");
		IOT_DEBUG("Response Type: %s. adv.type : %s", g_variant_get_type_string(ret), "peripheral");
	}
	/*if (g_strcmp0(property_name, "Flags") ==0)
	{
		static const guint8 flags = 0x04;
		ret = g_variant_new_variant(g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, &flags, 1, sizeof(guint8)));
		IOT_DEBUG("Response Flags: %s", g_variant_get_type_string(ret));
	}*/

	else if (g_strcmp0(property_name, "ManufacturerData") == 0)
	{
		GVariantBuilder *inner_builder = NULL;
		GVariantBuilder *builder1 = NULL;
		GVariant *desc_val = NULL;

		if (g_manufacturer_data_len <= 0)
		{
			return NULL;
		}

		inner_builder = g_variant_builder_new(G_VARIANT_TYPE("a{qv}"));

		/* Value */
		builder1 = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

		for (int i = 0; i < MFDATA_PACKET_MAX_LEN; i++)
		{
			g_variant_builder_add(builder1, "y", g_manufacturer_data[i]);
		}

		desc_val = g_variant_new("ay", builder1);
		IOT_DEBUG("Response Type: %s", g_variant_get_type_string(desc_val));
		g_variant_builder_add(inner_builder, "{qv}", g_manufacturer_code, desc_val);

		ret = g_variant_new("a{qv}", inner_builder);
		IOT_DEBUG("Response Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "ManufacturerDataSR") == 0)
	{
		GVariantBuilder *inner_builder = NULL;
		GVariantBuilder *builder1 = NULL;
		GVariant *desc_val = NULL;

		if (g_manufacturer_data_len <= MFDATA_PACKET_MAX_LEN)
		{
			return NULL;
		}

		inner_builder = g_variant_builder_new(G_VARIANT_TYPE("a{qv}"));

		/* Value */
		builder1 = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

		for (int i = MFDATA_PACKET_MAX_LEN; i < g_manufacturer_data_len; i++)
		{
			g_variant_builder_add(builder1, "y", g_manufacturer_data[i]);
		}

		desc_val = g_variant_new("ay", builder1);
		IOT_DEBUG("Response Type: %s", g_variant_get_type_string(desc_val));
		g_variant_builder_add(inner_builder, "{qv}", g_manufacturer_code, desc_val);

		ret = g_variant_new("a{qv}", inner_builder);
		IOT_DEBUG("Response Type: %s", g_variant_get_type_string(ret));
	}
	else if (g_strcmp0(property_name, "LocalName") == 0)
	{
		ret = g_variant_new("s", g_local_name);
		IOT_DEBUG("Response Type: %s", g_variant_get_type_string(ret));
	}
	return ret;
}

static gboolean
handle_set_property(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *property_name,
					GVariant *value,
					GError **error,
					gpointer user_data)
{
	IOT_DEBUG("Property Name: %s", property_name);
	if (g_strcmp0(property_name, "Type") == 0)
	{
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "RawAdvertisement") == 0)
	{
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else if (g_strcmp0(property_name, "RawScanResponseData") == 0)
	{
		g_set_error(error, g_quark_from_string("SetPropertyFailed"), 1,
					"Unable to set Property");
	}
	else
	{
		g_set_error(error,
					G_IO_ERROR,
					G_IO_ERROR_FAILED,
					"Hello AGAIN %s. I thought I said writing this property "
					"always results in an error. kthxbye",
					sender);
	}

	return *error == NULL;
}

static const GDBusInterfaceVTable interface_vtable =
	{
		handle_method_call,
		handle_get_property,
		handle_set_property};

/* ---------------------------------------------------------------------------------------------------- */

int get_bt_dev_address(uint8_t mac_address[6])
{
	int ret;
	GVariant *reply;
	GVariant *iter;
	char *addr;

	ret = gdbus_method_call_sync((char *)BLUEZ_SERVICE_NAME,
								 (char *)HCI_OBJECT_PATH,
								 (char *)DBUS_PROP_IFACE,
								 (char *)"Get",
								 g_variant_new("(ss)", ADAPTER_IFACE,
											   "Address"),
								 &reply);
	if (ret)
	{
		IOT_ERROR("error while fetching apscan mode of the interface %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &iter);
	g_variant_get(iter, "s", &addr);

	IOT_DEBUG("bd_addr = %s", addr);
	sscanf(addr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
			&mac_address[0],
			&mac_address[1],
			&mac_address[2],
			&mac_address[3],
			&mac_address[4],
			&mac_address[5]);

	g_variant_unref(iter);
	g_variant_unref(reply);
	return 0;
}

void start_advertisement_server()
{
	registration_id = gdbus_register_object(ADVERTISEMENT_PATH, introspection_xml, interface_vtable);
}

void stop_advertisement_server()
{
	g_dbus_connection_unregister_object(get_gdbus_connection(), registration_id);
}

void start_advertisement()
{
	IOT_DEBUG("advertisement: Start advertisement");
	char *adapter_path = NULL;

	adapter_path = find_bluez_adapter();
	gdbus_method_call_async((char *)BLUEZ_SERVICE_NAME,
							adapter_path,
							(char *)LE_ADVERTISING_MANAGER_IFACE,
							(char *)"RegisterAdvertisement",
							g_variant_new("(oa{sv})", ADVERTISEMENT_PATH, NULL),
							bluez_gdbus_call_async_cb,
							(gpointer) "RegisterAdvertisement");
	g_free(adapter_path);
}

int set_advertisement_data(uint16_t mn_code, uint8_t *mn_data, size_t mn_data_len, char *local_name)
{
	g_manufacturer_code = mn_code;
	memcpy(g_manufacturer_data, mn_data, mn_data_len);
	g_manufacturer_data_len = mn_data_len;
	memset(g_local_name, 0, sizeof(g_local_name));
	strncpy(g_local_name, local_name, strlen(local_name));
	return 0;
}

void stop_advertisement()
{
	char *adapter_path = NULL;

	adapter_path = find_bluez_adapter();
	gdbus_method_call_async((char *)BLUEZ_SERVICE_NAME,
							adapter_path,
							(char *)LE_ADVERTISING_MANAGER_IFACE,
							(char *)"UnregisterAdvertisement",
							g_variant_new("(o)", ADVERTISEMENT_PATH),
							bluez_gdbus_call_async_cb,
							(gpointer) "UnregisterAdvertisement");
	g_free(adapter_path);
}

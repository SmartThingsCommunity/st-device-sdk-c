/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include "wifi_supplicant.h"

#include <dirent.h>
#include <errno.h>
#include <gio/gio.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gdbus/gdbus_util.h"
#include "iot_bsp_wifi.h"
#include "iot_debug.h"

#define SUPPLICANT_PROP_INTERFACE "org.freedesktop.DBus.Properties"
#define SUPPLICANT_SERVICE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH "/fi/w1/wpa_supplicant1"

#define INTERFACE_UNKNOWN_ERROR 36

#define WIRELESS_CTRL_INTF_PATH "/sys/class/net"
#define PID_DIRECTORY "/var/run"

#define WIFI_KEY_MGMT_NONE "none"
#define WIFI_KEY_MGMT_WEP "wep"
#define WIFI_KEY_MGMT_PSK "psk"
#define WIFI_KEY_MGMT_EAP "eap"
#define WIFI_KEY_MGMT_SAE "sae"

#define WIFI_FREQ_SUPPORT_CMD "iw phy"
#define WIFI_FREQ_5GHZ_STR "Band 2"

static char *g_softap_iface;
static char *g_iface;
static char *g_network;
static GDBusConnection *g_connection;

static guint g_prop_sub_id;
static guint g_bss_added_sub_id;
static guint g_bss_removed_sub_id;
static guint g_bss_prop_sub_id;
/* scan cache maintained by BSSAdded/BSSRemoved signals: BSS object path -> iot_wifi_scan_result_t* */
static GHashTable *g_bss_table;
static GMutex g_bss_lock;
extern bool g_scanning;
extern iot_wifi_status g_wifi_status;
extern iot_wifi_disconnected_reason g_last_disconnected_reason;

static int supplicant_gdbus_method_call_sync(char *service, char *object_path, char *iface, char *method,
                                             GVariant *parameter, GVariant **reply)
{
    g_autoptr(GError) error = NULL;

    if (!g_connection)
        return -EINVAL;

    *reply = g_dbus_connection_call_sync(g_connection, service, object_path, iface, method, parameter, NULL,
                                         G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
    if (error) {
        IOT_ERROR("Error while sending dbus method call %s", error->message);

        int ret;
        ret = error->code;
        g_clear_error(&error);
        return ret;
    }
    return 0;
}

int supplicant_get_wireless_interface(char **ctrl_ifname)
{
    struct dirent *dent;

    DIR *dir = opendir(WIRELESS_CTRL_INTF_PATH);
    if (dir) {
        while ((dent = readdir(dir)) != NULL) {
            if (dent->d_name[0] == 'w' && dent->d_name[1] == 'l') {
                *ctrl_ifname = strdup(dent->d_name);
                closedir(dir);
                return 0;
            }
        }
        closedir(dir);
    }
    return -ENOENT;
}

static int supplicant_get_interface(char *ctrl_ifname, char **iface)
{
    int ret;
    char *temp;
    GVariant *reply;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, SUPPLICANT_PATH, SUPPLICANT_INTERFACE, "GetInterface",
                                            g_variant_new("(s)", (const gchar *)ctrl_ifname), &reply);
    if (ret) {
        IOT_ERROR("error while sending get interface method call %d", ret);
        return ret;
    }
    g_variant_get(reply, "(&o)", &temp);
    *iface = g_strdup(temp);
    IOT_DEBUG("WPA supplicant active interface:%s", *iface);

    g_variant_unref(reply);
    return 0;
}

static int supplicant_remove_interface(char *iface)
{
    int ret;
    GVariant *reply;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, SUPPLICANT_PATH, SUPPLICANT_INTERFACE,
                                            "RemoveInterface", g_variant_new("(o)", iface), &reply);
    if (ret) {
        IOT_ERROR("error while sending remove interface method call %d", ret);
        return -1;
    }
    return 0;
}

static int supplicant_create_interface(char *ctrl_ifname, char **iface)
{
    int ret;
    char *temp;
    GVariant *reply;
    GVariant *parameter;
    GVariantBuilder *builder;

    builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(builder, "{sv}", "Ifname", g_variant_new_string(ctrl_ifname));
    parameter = g_variant_builder_end(builder);
    g_variant_builder_unref(builder);

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, SUPPLICANT_PATH, SUPPLICANT_INTERFACE,
                                            "CreateInterface", g_variant_new_tuple(&parameter, 1), &reply);
    if (ret) {
        IOT_ERROR("error while sending create interface method call: %d", ret);
        return -1;
    }

    g_variant_get(reply, "(&o)", &temp);
    *iface = g_strdup(temp);
    IOT_DEBUG("WPA supplicant new interface:%s", *iface);

    g_variant_unref(reply);
    return 0;
}

static int supplicant_set_interface(char *iface, int ap_scan)
{
    int ret;
    GVariant *reply;

    ret = supplicant_gdbus_method_call_sync(
        SUPPLICANT_SERVICE, iface, SUPPLICANT_PROP_INTERFACE, "Set",
        g_variant_new("(ssv)", SUPPLICANT_INTERFACE ".Interface", "ApScan", g_variant_new("u", ap_scan)), &reply);
    if (ret) {
        IOT_ERROR("error while updating ap_scan mode of the interface %d", ret);
        return -1;
    }
    return 0;
}

static int supplicant_get_apscan_mode(char *iface, int *mode)
{
    int ret;
    GVariant *reply;
    GVariant *iter;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, iface, SUPPLICANT_PROP_INTERFACE, "Get",
                                            g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "ApScan"), &reply);
    if (ret) {
        IOT_ERROR("error while fetching apscan mode of the interface %d", ret);
        return -1;
    }
    g_variant_get(reply, "(v)", &iter);
    g_variant_get(iter, "u", mode);

    g_variant_unref(iter);
    g_variant_unref(reply);
    return 0;
}

static int supplicant_configure_interface(char **iface, int mode)
{
    char *ctrl_ifname;
    char *temp_iface;
    int apscan_mode;
    int ret;

    ret = supplicant_get_wireless_interface(&ctrl_ifname);
    if (ret) {
        IOT_ERROR("Unable to fetch wireless interface name %d", ret);
        return -1;
    }

    ret = supplicant_get_interface(ctrl_ifname, &temp_iface);
    if (ret) {
        if (ret != INTERFACE_UNKNOWN_ERROR)
            return -1;

        ret = supplicant_create_interface(ctrl_ifname, &temp_iface);
        if (ret) {
            IOT_ERROR("unable to send create interface method call: %d", ret);
            return -1;
        }

        ret = supplicant_set_interface(temp_iface, mode);
        if (ret) {
            IOT_ERROR("unable to send set interface method call: %d", ret);
            g_free(temp_iface);
            return -1;
        }

        *iface = temp_iface;
        return 0;
    }

    supplicant_get_apscan_mode(temp_iface, &apscan_mode);
    if (apscan_mode == mode) {
        IOT_INFO("already in required mode");
        *iface = temp_iface;
        return 0;
    }

    ret = supplicant_remove_interface(temp_iface);
    g_free(temp_iface);
    if (ret) {
        IOT_ERROR("unable to send remove interface method call: %d", ret);
        return -1;
    }

    if (mode == 1)
        g_softap_iface = NULL;
    else
        g_iface = NULL;

    ret = supplicant_create_interface(ctrl_ifname, &temp_iface);
    if (ret) {
        IOT_ERROR("unable to send get interface method call: %d", ret);
        return -1;
    }

    ret = supplicant_set_interface(temp_iface, mode);
    if (ret) {
        IOT_ERROR("unable to send set interface method call: %d", ret);
        g_free(temp_iface);
        return -1;
    }

    *iface = temp_iface;
    return 0;
}

/* Fill an ap_record from a fi.w1.wpa_supplicant1.BSS property dictionary
 * (as returned by GetAll and carried in the BSSAdded signal payload). */
static int supplicant_parse_bss_properties(GVariant *props, iot_wifi_scan_result_t *ap_record)
{
    GVariant *prop;
    GVariant *value;
    GVariantIter *iter;
    GVariantIter *key_algo;
    char *key;
    char *alg;
    iot_wifi_auth_mode_t auth;
    uint8_t byt;
    int i;

    prop = g_variant_lookup_value(props, "BSSID", G_VARIANT_TYPE_BYTESTRING);
    if (!prop) {
        IOT_ERROR("BSS properties have no BSSID");
        return -1;
    }
    g_variant_get(prop, "ay", &iter);
    for (i = 0; g_variant_iter_loop(iter, "y", &byt) && i < IOT_WIFI_MAX_BSSID_LEN; i++) {
        ap_record->bssid[i] = byt;
    }
    g_variant_iter_free(iter);
    g_variant_unref(prop);

    prop = g_variant_lookup_value(props, "SSID", G_VARIANT_TYPE_BYTESTRING);
    if (!prop) {
        IOT_ERROR("BSS properties have no SSID");
        return -1;
    }
    g_variant_get(prop, "ay", &iter);
    for (i = 0; g_variant_iter_loop(iter, "y", &byt) && i < IOT_WIFI_MAX_SSID_LEN; i++) {
        ap_record->ssid[i] = byt;
    }
    ap_record->ssid[i] = '\0';
    ap_record->ssid_len = i;
    /* wpa_supplicant provides raw SSID bytes without any encoding guarantee */
    ap_record->hexssid_needed = 1;
    g_variant_iter_free(iter);
    g_variant_unref(prop);

    auth = IOT_WIFI_AUTH_OPEN;
    prop = g_variant_lookup_value(props, "WPA", G_VARIANT_TYPE_VARDICT);
    if (prop) {
        g_variant_get(prop, "a{sv}", &iter);
        while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
            if (strcmp(key, "KeyMgmt") == 0) {
                g_variant_get(value, "as", &key_algo);
                while (g_variant_iter_loop(key_algo, "s", &alg)) {
                    if (strstr(alg, WIFI_KEY_MGMT_PSK))
                        auth = IOT_WIFI_AUTH_WPA_PSK;
                }
                g_variant_iter_free(key_algo);
            } else if (strcmp(key, "Group") == 0) {
                g_variant_get(value, "&s", &alg);
                if (strstr(alg, WIFI_KEY_MGMT_WEP))
                    auth = IOT_WIFI_AUTH_WEP;
            }
        }
        g_variant_iter_free(iter);
        g_variant_unref(prop);
    }

    prop = g_variant_lookup_value(props, "RSN", G_VARIANT_TYPE_VARDICT);
    if (prop) {
        bool has_sae = false;

        g_variant_get(prop, "a{sv}", &iter);
        while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
            if (strcmp(key, "KeyMgmt") == 0) {
                g_variant_get(value, "as", &key_algo);
                while (g_variant_iter_loop(key_algo, "s", &alg)) {
                    if (strstr(alg, WIFI_KEY_MGMT_SAE)) {
                        has_sae = true;
                    } else if (strstr(alg, WIFI_KEY_MGMT_PSK)) {
                        if (auth == IOT_WIFI_AUTH_WPA_PSK)
                            auth = IOT_WIFI_AUTH_WPA_WPA2_PSK;
                        else
                            auth = IOT_WIFI_AUTH_WPA2_PSK;
                    } else if (strstr(alg, WIFI_KEY_MGMT_EAP)) {
                        auth = IOT_WIFI_AUTH_WPA2_ENTERPRISE;
                    }
                }
                g_variant_iter_free(key_algo);
            }
        }

        /* an AP advertising SAE is reported as WPA3, including
         * WPA2/WPA3 transition mode (sae + psk in RSN KeyMgmt) */
        if (has_sae)
            auth = IOT_WIFI_AUTH_WPA3_PERSONAL;

        g_variant_iter_free(iter);
        g_variant_unref(prop);
    }
    ap_record->authmode = auth;

    prop = g_variant_lookup_value(props, "Frequency", G_VARIANT_TYPE_UINT16);
    if (prop) {
        ap_record->freq = g_variant_get_uint16(prop);
        g_variant_unref(prop);
    }

    prop = g_variant_lookup_value(props, "Signal", G_VARIANT_TYPE_INT16);
    if (prop) {
        ap_record->rssi = (int8_t)g_variant_get_int16(prop);
        g_variant_unref(prop);
    }
    return 0;
}

static int supplicant_get_scanned_ap_record(char *bss_path, iot_wifi_scan_result_t *ap_record)
{
    GVariant *reply;
    GVariant *props;
    int ret;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, bss_path, SUPPLICANT_PROP_INTERFACE, "GetAll",
                                            g_variant_new("(s)", SUPPLICANT_INTERFACE ".BSS"), &reply);
    if (ret) {
        IOT_ERROR("error while getting properties of BSS %d", ret);
        return -1;
    }

    g_variant_get(reply, "(@a{sv})", &props);
    ret = supplicant_parse_bss_properties(props, ap_record);
    if (ret == 0 && ap_record->ssid_len == 0) {
        IOT_WARN("skip hidden ssid, %s", bss_path);
        ret = -1;
    }

    g_variant_unref(props);
    g_variant_unref(reply);
    return ret;
}

static int supplicant_variant_builder(struct wpa_ssid *ssid, GVariant **parameter)
{
    GVariantBuilder *builder;
    builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

    if (ssid == NULL) {
        IOT_ERROR("invalid wpa_ssid parameter");
        return -EINVAL;
    }

    g_variant_builder_add(builder, "{sv}", "ssid", g_variant_new_string(ssid->ssid));
    g_variant_builder_add(builder, "{sv}", "mode", g_variant_new("u", ssid->mode));
    g_variant_builder_add(builder, "{sv}", "key_mgmt", g_variant_new_string(ssid->key_mgmt));
    /* wpa_supplicant rejects a psk passphrase outside 8..63 chars,
     * so it must not be set for an open network (key_mgmt "NONE") or
     * for an SAE-only password longer than 63 chars */
    if (strstr(ssid->key_mgmt, "WPA-PSK") != NULL) {
        size_t pswd_len = strlen(ssid->pswd);
        if (pswd_len >= 8 && pswd_len <= 63)
            g_variant_builder_add(builder, "{sv}", "psk", g_variant_new_string(ssid->pswd));
    }
    if (strstr(ssid->key_mgmt, "SAE") != NULL) {
        g_variant_builder_add(builder, "{sv}", "sae_password", g_variant_new_string(ssid->pswd));
        g_variant_builder_add(builder, "{sv}", "ieee80211w", g_variant_new("u", ssid->ieee80211w));
    }
    g_variant_builder_add(builder, "{sv}", "scan_ssid", g_variant_new("u", ssid->hidden));

    *parameter = g_variant_builder_end(builder);
    g_variant_builder_unref(builder);
    return 0;
}

static int supplicant_add_network(char *iface, struct wpa_ssid *ssid)
{
    GVariant *reply;
    GVariant *parameter;
    char *temp;
    int ret;

    supplicant_variant_builder(ssid, &parameter);
    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, iface, SUPPLICANT_INTERFACE ".Interface", "AddNetwork",
                                            g_variant_new_tuple(&parameter, 1), &reply);

    if (ret) {
        IOT_ERROR("error while sending add network method call %d", ret);
        return -1;
    }

    g_variant_get(reply, "(&o)", &temp);
    g_network = g_strdup(temp);
    IOT_DEBUG("added new network %s", g_network);

    g_variant_unref(reply);
    return 0;
}

static int supplicant_remove_network(char *iface)
{
    GVariant *reply;
    int ret;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, iface, SUPPLICANT_INTERFACE ".Interface",
                                            "RemoveNetwork", g_variant_new("(o)", g_network), &reply);
    if (ret) {
        IOT_ERROR("error while removing network %d", ret);
        return -1;
    }
    return 0;
}

static int supplicant_select_network(char *iface)
{
    GVariant *reply;
    GVariant *parameter;
    int ret;

    parameter = g_variant_new("o", g_network);
    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, iface, SUPPLICANT_INTERFACE ".Interface",
                                            "SelectNetwork", g_variant_new_tuple(&parameter, 1), &reply);
    if (ret) {
        IOT_ERROR("error while sending select network method call: %d", ret);
        return -1;
    }
    return 0;
}

static int supplicant_enable_network(void)
{
    GVariant *reply;
    int ret;

    ret = supplicant_gdbus_method_call_sync(
        SUPPLICANT_SERVICE, g_network, SUPPLICANT_PROP_INTERFACE, "Set",
        g_variant_new("(ssv)", SUPPLICANT_INTERFACE ".Network", "Enabled", g_variant_new("b", true)), &reply);
    if (ret) {
        IOT_ERROR("error while enabling the network %d", ret);
        return -1;
    }
    return 0;
}

static int supplicant_execute_command(const char *file_path, char *const args[], char *const envs[])
{
    int pid;
    int rv;
    errno = 0;

    pid = fork();
    switch (pid) {
        case -1:
            IOT_ERROR("fork failed");
            return -1;
        case 0:
            if (execve(file_path, args, envs) == -1) {
                IOT_ERROR("failed to execute command (%s)", strerror(errno));
                exit(1);
                return -1;
            }
            break;
        default:
            if (waitpid(pid, &rv, 0) == -1)
                IOT_DEBUG("wait pid (%u) rv (%d)", pid, rv);
            break;
    }
    return pid;
}

static int supplicant_fetch_pid(char *process_name)
{
    int max_pid_len = 32768;
    char line[max_pid_len];
    char command[100];

    snprintf(command, sizeof(command), "pidof %s", process_name);
    FILE *proc = popen(command, "r");
    if (fgets(line, max_pid_len, proc)) {
        pid_t pid = strtoul(line, NULL, 10);
        pclose(proc);
        return pid;
    }
    pclose(proc);
    return -1;
}

int supplicant_turn_wifi_off(void)
{
    int ret;

    IOT_DEBUG("Turning off wifi");
    ret = system("sudo nmcli radio wifi off");
    if (ret == -1 || ret == 127) {
        IOT_ERROR("system() invoke error(%d)", ret);
        return -1;
    }

    IOT_DEBUG("Unblocking wifi");
    ret = system("sudo rfkill unblock wifi");
    if (ret == -1 || ret == 127) {
        IOT_ERROR("system() invoke error(%d)", ret);
        return -1;
    }
    return 0;
}

int supplicant_turn_wifi_on(void)
{
    int ret;

    IOT_DEBUG("Turning on wifi");
    ret = system("sudo nmcli radio wifi on");
    if (ret == -1 || ret == 127) {
        IOT_ERROR("system() invoke error(%d)", ret);
        return -1;
    }
    return 0;
}

void supplicant_initialise_wifi(void)
{
    char *const args_kill_wpa[] = {"/usr/bin/killall", "wpa_supplicant", NULL};
    char *const envs[] = {NULL};
    int ret;

    ret = supplicant_execute_command(args_kill_wpa[0], &args_kill_wpa[0], envs);
    if (ret < 0)
        IOT_INFO("failed to kill wpa_supplicant (%d)", ret);

    sleep(1);

    supplicant_leave_network();
    supplicant_stop_station();
    supplicant_stop_softap();
}

int supplicant_is_scan_mode(void)
{
    if (g_iface || g_softap_iface)
        return 1;
    return 0;
}

static int supplicant_query_scanning()
{
    GVariant *reply;
    GVariant *prop;
    gboolean scanning;
    int ret;

    ret =
        supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, g_iface, SUPPLICANT_PROP_INTERFACE, "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "Scanning"), &reply);
    if (ret) {
        IOT_ERROR("error while getting Scanning property of interface %d", ret);
        return -1;
    }

    g_variant_get(reply, "(v)", &prop);
    scanning = g_variant_get_boolean(prop);

    g_variant_unref(prop);
    g_variant_unref(reply);
    return scanning ? 1 : 0;
}

int supplicant_start_scan(void)
{
    GVariant *reply;
    GVariant *parameter;
    GVariantBuilder *builder;
    int ret;

    builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(builder, "{sv}", "Type", g_variant_new_string("active"));
    parameter = g_variant_builder_end(builder);
    g_variant_builder_unref(builder);

    IOT_INFO("Triggered a scan");
    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, g_iface ? g_iface : g_softap_iface,
                                            SUPPLICANT_INTERFACE ".Interface", "Scan",
                                            g_variant_new_tuple(&parameter, 1), &reply);
    if (ret) {
        IOT_ERROR("error while sending scan method call %d", ret);
        return -1;
    }
    return 0;
}

static void supplicant_bss_added_cb(GDBusConnection *connection, const gchar *sender_name, const gchar *object_path,
                                    const gchar *interface_name, const gchar *signal_name, GVariant *parameters,
                                    gpointer user_data)
{
    const gchar *bss_path;
    GVariant *props;
    iot_wifi_scan_result_t *ap_record;

    g_variant_get(parameters, "(&o@a{sv})", &bss_path, &props);

    ap_record = calloc(1, sizeof(iot_wifi_scan_result_t));
    if (ap_record && supplicant_parse_bss_properties(props, ap_record) == 0 && ap_record->ssid_len > 0) {
        g_mutex_lock(&g_bss_lock);
        if (g_bss_table) {
            g_hash_table_replace(g_bss_table, g_strdup(bss_path), ap_record);
            ap_record = NULL;
        }
        g_mutex_unlock(&g_bss_lock);
    }
    /* a BSS with an empty SSID (hidden AP) is kept out of the scan cache */
    free(ap_record);
    g_variant_unref(props);
}

static void supplicant_bss_removed_cb(GDBusConnection *connection, const gchar *sender_name, const gchar *object_path,
                                      const gchar *interface_name, const gchar *signal_name, GVariant *parameters,
                                      gpointer user_data)
{
    const gchar *bss_path;

    g_variant_get(parameters, "(&o)", &bss_path);

    g_mutex_lock(&g_bss_lock);
    if (g_bss_table)
        g_hash_table_remove(g_bss_table, bss_path);
    g_mutex_unlock(&g_bss_lock);
}

/* a re-scanned BSS is not added again - its RSSI arrives as a
 * PropertiesChanged signal on the BSS object */
static void supplicant_bss_prop_changed_cb(GDBusConnection *connection, const gchar *sender_name,
                                           const gchar *object_path, const gchar *interface_name,
                                           const gchar *signal_name, GVariant *parameters, gpointer user_data)
{
    GVariant *changed;
    GVariant *prop;
    iot_wifi_scan_result_t *ap_record;

    g_variant_get(parameters, "(&s@a{sv}as)", NULL, &changed, NULL);

    prop = g_variant_lookup_value(changed, "Signal", G_VARIANT_TYPE_INT16);
    if (prop) {
        g_mutex_lock(&g_bss_lock);
        ap_record = g_bss_table ? g_hash_table_lookup(g_bss_table, object_path) : NULL;
        if (ap_record)
            ap_record->rssi = (int8_t)g_variant_get_int16(prop);
        g_mutex_unlock(&g_bss_lock);
        g_variant_unref(prop);
    }
    g_variant_unref(changed);
}

/* BSSAdded only reports BSSs discovered after the subscription - seed the
 * cache with the BSSs wpa_supplicant already holds for the interface */
static void supplicant_seed_bss_table(void)
{
    GVariant *reply;
    GVariant *temp;
    GVariantIter *iter;
    char *bss_path;
    iot_wifi_scan_result_t *ap_record;
    int ret;

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, g_iface ? g_iface : g_softap_iface,
                                            SUPPLICANT_PROP_INTERFACE, "Get",
                                            g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "BSSs"), &reply);
    if (ret) {
        IOT_ERROR("error while fetching BSSs of the interface %d", ret);
        return;
    }

    g_variant_get(reply, "(v)", &temp);
    g_variant_get(temp, "ao", &iter);

    while (g_variant_iter_loop(iter, "o", &bss_path)) {
        ap_record = calloc(1, sizeof(iot_wifi_scan_result_t));
        if (!ap_record)
            break;
        if (supplicant_get_scanned_ap_record(bss_path, ap_record) == 0) {
            g_mutex_lock(&g_bss_lock);
            g_hash_table_replace(g_bss_table, g_strdup(bss_path), ap_record);
            g_mutex_unlock(&g_bss_lock);
        } else {
            free(ap_record);
        }
    }
    g_variant_iter_free(iter);
    g_variant_unref(temp);
    g_variant_unref(reply);
}

static void supplicant_unsubscribe_bss_signals(void)
{
    if (g_bss_added_sub_id) {
        g_dbus_connection_signal_unsubscribe(g_connection, g_bss_added_sub_id);
        g_bss_added_sub_id = 0;
    }
    if (g_bss_removed_sub_id) {
        g_dbus_connection_signal_unsubscribe(g_connection, g_bss_removed_sub_id);
        g_bss_removed_sub_id = 0;
    }
    if (g_bss_prop_sub_id) {
        g_dbus_connection_signal_unsubscribe(g_connection, g_bss_prop_sub_id);
        g_bss_prop_sub_id = 0;
    }

    g_mutex_lock(&g_bss_lock);
    if (g_bss_table)
        g_hash_table_remove_all(g_bss_table);
    g_mutex_unlock(&g_bss_lock);
}

static void supplicant_subscribe_bss_signals(void)
{
    if (!g_connection || (!g_iface && !g_softap_iface))
        return;

    /* signal callbacks are dispatched by the shared gdbus main loop */
    if (gdbus_init_loop() < 0) {
        IOT_WARN("failed to start gdbus loop, keep reading scan results on demand");
        return;
    }

    supplicant_unsubscribe_bss_signals();

    g_mutex_lock(&g_bss_lock);
    if (!g_bss_table)
        g_bss_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free);
    g_mutex_unlock(&g_bss_lock);

    /* the interface object path is not filtered, so the subscription stays
     * valid across a station/softap interface switch */
    g_bss_added_sub_id = g_dbus_connection_signal_subscribe(
        g_connection, SUPPLICANT_SERVICE, SUPPLICANT_INTERFACE ".Interface", "BSSAdded", NULL, NULL,
        G_DBUS_SIGNAL_FLAGS_NONE, supplicant_bss_added_cb, NULL, NULL);
    g_bss_removed_sub_id = g_dbus_connection_signal_subscribe(
        g_connection, SUPPLICANT_SERVICE, SUPPLICANT_INTERFACE ".Interface", "BSSRemoved", NULL, NULL,
        G_DBUS_SIGNAL_FLAGS_NONE, supplicant_bss_removed_cb, NULL, NULL);
    g_bss_prop_sub_id = g_dbus_connection_signal_subscribe(
        g_connection, SUPPLICANT_SERVICE, SUPPLICANT_PROP_INTERFACE, "PropertiesChanged", NULL,
        SUPPLICANT_INTERFACE ".BSS", G_DBUS_SIGNAL_FLAGS_NONE, supplicant_bss_prop_changed_cb, NULL, NULL);

    supplicant_seed_bss_table();
}

uint16_t supplicant_get_scanned_ap_list(iot_wifi_scan_result_t *ap_list)
{
    int ret;
    uint16_t i;
    GVariant *reply;
    GVariant *temp;
    GVariantIter *iter;
    char *bss_path;
    iot_wifi_scan_result_t ap_record;

    if (g_bss_added_sub_id) {
        GHashTableIter table_iter;
        gpointer record;

        g_mutex_lock(&g_bss_lock);
        g_hash_table_iter_init(&table_iter, g_bss_table);
        for (i = 0; i < IOT_WIFI_MAX_SCAN_RESULT && g_hash_table_iter_next(&table_iter, NULL, &record); i++) {
            memcpy(&ap_list[i], record, sizeof(iot_wifi_scan_result_t));
        }
        g_mutex_unlock(&g_bss_lock);
        return i;
    }

    /* fallback when the BSS signal subscription is not active */
    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, g_iface ? g_iface : g_softap_iface,
                                            SUPPLICANT_PROP_INTERFACE, "Get",
                                            g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "BSSs"), &reply);
    if (ret) {
        IOT_ERROR("error while fetching BSSs of the interface %d", ret);
        return 0;
    }

    g_variant_get(reply, "(v)", &temp);
    g_variant_get(temp, "ao", &iter);

    for (i = 0; g_variant_iter_loop(iter, "o", &bss_path) && i < IOT_WIFI_MAX_SCAN_RESULT; i++) {
        memset(&ap_record, 0, sizeof(ap_record));
        if (supplicant_get_scanned_ap_record(bss_path, &ap_record) == 0) {
            memcpy(ap_list[i].ssid, ap_record.ssid, ap_record.ssid_len);
            memcpy(ap_list[i].bssid, ap_record.bssid, IOT_WIFI_MAX_BSSID_LEN);

            ap_list[i].ssid_len = ap_record.ssid_len;
            ap_list[i].hexssid_needed = ap_record.hexssid_needed;
            ap_list[i].rssi = ap_record.rssi;
            ap_list[i].freq = ap_record.freq;
            ap_list[i].authmode = ap_record.authmode;
        } else {
            i--;
        }
    }
    g_variant_iter_free(iter);
    g_variant_unref(temp);
    g_variant_unref(reply);
    return i;
}

static iot_wifi_disconnected_reason _map_disconnect_reason(int reason)
{
    /* a negative value means a locally generated disconnect */
    switch (abs(reason)) {
        case WLAN_REASON_PREV_AUTH_NOT_VALID:
        case WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT:
        case WLAN_REASON_IEEE_802_1X_AUTH_FAILED:
            return IOT_WIFI_DISCONNECTED_REASON_AUTH_FAIL;
        case WLAN_REASON_DISASSOC_AP_BUSY:
            return IOT_WIFI_DISCONNECTED_REASON_ASSOC_FAIL;
        case 0:
            /* no disconnect has been recorded on the interface */
            return IOT_WIFI_DISCONNECTED_REASON_UNKNOWN;
        default:
            return IOT_WIFI_DISCONNECTED_REASON_CONNECTION_FAIL;
    }
}

static int supplicant_get_disconnect_reason(int *reason)
{
    GVariant *reply;
    GVariant *prop;
    int ret;

    if (!g_iface) {
        IOT_ERROR("no interface available");
        return -1;
    }

    ret = supplicant_gdbus_method_call_sync(
        SUPPLICANT_SERVICE, g_iface, SUPPLICANT_PROP_INTERFACE, "Get",
        g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "DisconnectReason"), &reply);
    if (ret) {
        IOT_ERROR("error while getting DisconnectReason property of interface %d", ret);
        return -1;
    }

    g_variant_get(reply, "(v)", &prop);
    g_variant_get(prop, "i", reason);

    g_variant_unref(prop);
    g_variant_unref(reply);
    return 0;
}

static void supplicant_prop_changed_cb(GDBusConnection *connection, const gchar *sender_name, const gchar *object_path,
                                       const gchar *interface_name, const gchar *signal_name, GVariant *parameters,
                                       gpointer user_data)
{
    GVariantIter *iter;
    const gchar *key;
    GVariant *value;

    g_variant_get(parameters, "(&sa{sv}as)", NULL, &iter, NULL);

    while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
        if (strcmp(key, "State") == 0) {
            const char *state = g_variant_get_string(value, NULL);
            IOT_DEBUG("interface state: %s", state);

            if (strncmp(state, "completed", sizeof("completed")) == 0) {
                g_wifi_status = IOT_WIFI_STATUS_CONNECTED;
            } else if (strncmp(state, "disconnected", sizeof("disconnected")) == 0) {
                int disconnect_reason;
                g_wifi_status = IOT_WIFI_STATUS_DISCONNECTED;
                if (supplicant_get_disconnect_reason(&disconnect_reason) == 0) {
                    g_last_disconnected_reason = _map_disconnect_reason(disconnect_reason);
                }
            } else if (strncmp(state, "inactive", sizeof("inactive")) == 0) {
                g_wifi_status = IOT_WIFI_STATUS_IDLE;
            } else if (strncmp(state, "scanning", sizeof("scanning")) == 0) {
                g_wifi_status = IOT_WIFI_STATUS_SCANNING;
            } else {
                /* associating, authenticating, 4way_handshake, group_handshake */
                g_wifi_status = IOT_WIFI_STATUS_CONNECTING;
            }
        } else if (strcmp(key, "DisconnectReason") == 0) {
            int disconnect_reason = g_variant_get_int32(value);
            g_last_disconnected_reason = _map_disconnect_reason(disconnect_reason);
        } else if (strcmp(key, "Scanning") == 0) {
            g_scanning = g_variant_get_boolean(value);
            IOT_DEBUG("interface scanning: %d", g_scanning);
        }
    }

    g_variant_iter_free(iter);
}

static void supplicant_unsubscribe_prop_changed(void)
{
    if (g_prop_sub_id) {
        g_dbus_connection_signal_unsubscribe(g_connection, g_prop_sub_id);
        g_prop_sub_id = 0;
    }
}

static void supplicant_subscribe_prop_changed(void)
{
    if (!g_connection || !g_iface)
        return;

    /* signal callbacks are dispatched by the shared gdbus main loop */
    if (gdbus_init_loop() < 0) {
        IOT_WARN("failed to start gdbus loop, keep polling wifi state");
        return;
    }

    supplicant_unsubscribe_prop_changed();
    g_prop_sub_id = g_dbus_connection_signal_subscribe(
        g_connection, SUPPLICANT_SERVICE, SUPPLICANT_PROP_INTERFACE, "PropertiesChanged", g_iface,
        SUPPLICANT_INTERFACE ".Interface", G_DBUS_SIGNAL_FLAGS_NONE, supplicant_prop_changed_cb, NULL, NULL);

    g_scanning = (supplicant_query_scanning() > 0);
}

int supplicant_start_station(void)
{
    if (!g_connection) {
        g_autoptr(GError) error = NULL;
        g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
        if (error) {
            IOT_ERROR("failed to get gdbus connection %s", error->message);
            g_clear_error(&error);
            return -1;
        }
    }

    if (supplicant_stop_softap() == -1)
        return -1;

    g_free(g_iface);
    g_iface = NULL;
    /* the previous interface (if any) is gone - drop its subscription and cache */
    supplicant_unsubscribe_prop_changed();
    supplicant_unsubscribe_bss_signals();
    if (supplicant_configure_interface(&g_iface, 1) == -1) {
        IOT_ERROR("failed to configure network while starting station mode");
        return -1;
    }
    supplicant_subscribe_prop_changed();
    supplicant_subscribe_bss_signals();
    return 0;
}

int supplicant_stop_station(void)
{
    int ret;

    if (g_iface == NULL)
        return 0;

    ret = supplicant_remove_interface(g_iface);
    if (ret) {
        IOT_ERROR("unable to send remove interface method call: %d", ret);
        return -1;
    }

    g_free(g_iface);
    g_iface = NULL;
    supplicant_unsubscribe_prop_changed();
    supplicant_unsubscribe_bss_signals();
    return 0;
}

int supplicant_is_station_active(void)
{
    return (g_iface != NULL);
}

int supplicant_get_current_ap(iot_wifi_scan_result_t *ap_record)
{
    GVariant *reply;
    GVariant *prop;
    char *bss_path;
    int ret;

    if (!g_iface) {
        IOT_ERROR("no interface available");
        return -1;
    }

    ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE, g_iface, SUPPLICANT_PROP_INTERFACE, "Get",
                                            g_variant_new("(ss)", SUPPLICANT_INTERFACE ".Interface", "CurrentBSS"),
                                            &reply);
    if (ret) {
        IOT_ERROR("error while getting CurrentBSS property of interface %d", ret);
        return -1;
    }

    g_variant_get(reply, "(v)", &prop);
    g_variant_get(prop, "&o", &bss_path);

    /* "/" means the interface is not associated with a BSS */
    if (strncmp(bss_path, "/", sizeof("/")) == 0) {
        g_variant_unref(prop);
        g_variant_unref(reply);
        return -1;
    }

    ret = supplicant_get_scanned_ap_record(bss_path, ap_record);

    g_variant_unref(prop);
    g_variant_unref(reply);
    return ret;
}

int supplicant_join_network(char *ssid_key, char *password, iot_wifi_auth_mode_t authmode, int hidden)
{
    struct wpa_ssid ssid = {0};
    snprintf(ssid.ssid, sizeof(ssid.ssid), "%s", ssid_key);
    snprintf(ssid.pswd, sizeof(ssid.pswd), "%s", password);
    ssid.mode = WPAS_MODE_INFRA;

    if (authmode == IOT_WIFI_AUTH_OPEN)
        ssid.key_mgmt = "NONE";
    else if (authmode == IOT_WIFI_AUTH_WEP) {
        ssid.key_mgmt = "NONE";
    } else if (authmode == IOT_WIFI_AUTH_WPA3_PERSONAL) {
        /* allow WPA-PSK fallback so a WPA2/WPA3 transition-mode AP can
         * still be joined when the driver does not support SAE.
         * PMF optional: a WPA3-only AP that mandates PMF still
         * negotiates it, while legacy fallback stays possible. */
        ssid.key_mgmt = "SAE WPA-PSK";
        ssid.ieee80211w = 1;
    } else {
        ssid.key_mgmt = "WPA-PSK";
    }

    ssid.hidden = hidden;

    /* remove a previously configured network to avoid stale entries piling up */
    if (supplicant_leave_network() == -1) {
        IOT_WARN("failed to remove previous network");
        return -1;
    }

    if (supplicant_add_network(g_iface, &ssid) == -1) {
        IOT_ERROR("failed to add network while joining AP");
        return -1;
    }

    if (supplicant_select_network(g_iface) == -1) {
        IOT_ERROR("failed to select network while joining AP");
        return -1;
    }

    g_wifi_status = IOT_WIFI_STATUS_SCANNING;
    g_last_disconnected_reason = IOT_WIFI_DISCONNECTED_REASON_UNKNOWN;
    return 0;
}

int supplicant_leave_network(void)
{
    if (g_iface == NULL || g_network == NULL)
        return 0;

    if (supplicant_remove_network(g_iface) == -1) {
        IOT_ERROR("failed to remove network while leaving network");
        return -1;
    }

    g_free(g_network);
    g_network = NULL;
    return 0;
}

int supplicant_start_softap(char *ssid_name, char *pswd)
{
    struct wpa_ssid ssid = {0};

    if (!g_connection) {
        g_autoptr(GError) error = NULL;
        g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
        if (error) {
            IOT_ERROR("failed to get gdbus connection %s", error->message);
            g_clear_error(&error);
            return -1;
        }
    }

    if (supplicant_leave_network() == -1)
        return -1;

    g_free(g_softap_iface);
    g_softap_iface = NULL;
    if (supplicant_configure_interface(&g_softap_iface, 2) == -1) {
        IOT_ERROR("failed to configure network while starting softAP mode");
        return -1;
    }
    /* a scan can also run on the softap interface - keep the BSS cache alive */
    supplicant_subscribe_bss_signals();

    snprintf(ssid.ssid, sizeof(ssid.ssid), "%s", ssid_name);
    snprintf(ssid.pswd, sizeof(ssid.pswd), "%s", pswd);
    ssid.mode = WPAS_MODE_AP;
    ssid.key_mgmt = "WPA-PSK";
    ssid.hidden = 0;

    if (supplicant_add_network(g_softap_iface, &ssid) == -1) {
        IOT_ERROR("failed to add network in SoftAP mode");
        return -1;
    }

    if (supplicant_select_network(g_softap_iface) == -1) {
        IOT_ERROR("failed to select network in SoftAP mode");
        return -1;
    }

    if (supplicant_enable_network() == -1) {
        IOT_ERROR("failed to enable network in SoftAP mode");
        return -1;
    }
    return 0;
}

int supplicant_stop_softap(void)
{
    int ret;

    if (g_softap_iface == NULL || g_network == NULL)
        return 0;

    ret = supplicant_remove_network(g_softap_iface);
    if (ret) {
        IOT_ERROR("failed to remove network while stopping softAP");
        return -1;
    }

    g_free(g_network);
    g_network = NULL;
    return 0;
}

/* Parse `iw phy` command output and check whether
 * board supports only 2.4GHz or both 2.4GHz and 5GHz.
 */
int supplicant_get_freq_support(void)
{
    FILE *fp;
    int max_line_len = 500;
    char line[max_line_len];
    char cmd[20] = {0};

    strncpy(cmd, WIFI_FREQ_SUPPORT_CMD, sizeof(cmd) - 1);
    fp = popen(cmd, "r");
    while (fgets(line, max_line_len, fp)) {
        if (strstr(line, WIFI_FREQ_5GHZ_STR) != NULL) {
            pclose(fp);
            return 1;
        }
    }
    pclose(fp);
    return 0;
}

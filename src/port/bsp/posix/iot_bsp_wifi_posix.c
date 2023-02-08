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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <net/route.h>
#include <sys/types.h>
#include <pwd.h>

#include "iot_debug.h"
#include "iot_bsp_wifi.h"

#define IFACE_NAME	"wlan0"

static int _create_socket()
{
    int sockfd = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        IOT_ERROR("Can't get socket (%d, %s)", errno, strerror(errno));
        return -errno;
    }
    return sockfd;
}

iot_error_t iot_bsp_wifi_init()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	return 0;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	struct ifreq ifr;
	int sockfd = 0;
	iot_error_t err = IOT_ERROR_NONE;

	sockfd = _create_socket();
	if (sockfd < 0)
		return IOT_ERROR_READ_FAIL;

	strncpy(ifr.ifr_name, IFACE_NAME, IF_NAMESIZE);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		IOT_ERROR("ioctl(%d, %s): 0x%x", errno, strerror(errno), SIOCGIFHWADDR);
		err = IOT_ERROR_READ_FAIL;
		goto mac_out;
	}
	memcpy(wifi_mac->addr, ifr.ifr_hwaddr.sa_data, sizeof(wifi_mac->addr));

mac_out:
	close(sockfd);
	return err;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}

iot_error_t iot_bsp_wifi_register_event_cb(iot_bsp_wifi_event_cb_t cb)
{
	return IOT_ERROR_BAD_REQ;
}

void iot_bsp_wifi_clear_event_cb(void)
{
}

iot_wifi_auth_mode_bits_t iot_bsp_wifi_get_auth_mode(void)
{
	iot_wifi_auth_mode_bits_t supported_mode_bits = IOT_WIFI_AUTH_MODE_BIT_ALL;
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_ENTERPRISE);
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA3_PERSONAL);

	return supported_mode_bits;
}
/* ***************************************************************************
 *
 * Copyright (c) 2026 Samsung Electronics All Rights Reserved.
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

#include "iot_sntp.h"

#include <stdint.h>
#include <time.h>

#include "iot_bsp_system.h"
#include "iot_debug.h"
#include "port_net.h"

#define SNTP_PACKET_SIZE 48
#define SNTP_LI_VN_MODE 0x23 /* LI=0, VN=4, Mode=3 (client) */
#define SNTP_MODE_MASK 0x07
#define SNTP_MODE_SERVER 4
#define SNTP_LI_MASK 0xc0
#define SNTP_LI_ALARM 0xc0 /* clock unsynchronized */
#define SNTP_STRATUM_MAX 15
#define SNTP_TX_TIMESTAMP_OFFSET 40
#define SNTP_PORT "123"
#define SNTP_RESPONSE_TIMEOUT_MS 3000

/* Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01) */
#define SNTP_UNIX_OFFSET 2208988800UL
/* Unix time at the NTP era 1 rollover (2036-02-07): 2^32 - SNTP_UNIX_OFFSET */
#define SNTP_ERA1_UNIX_BASE 2085978496UL

static const char *sntp_servers[] = {
    "pool.ntp.org",
    "time.google.com",
};

static uint32_t _sntp_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static iot_error_t _sntp_query(const char *server, time_t *epoch)
{
    unsigned char pkt[SNTP_PACKET_SIZE] = {
        SNTP_LI_VN_MODE,
    };
    PORT_NET_CONTEXT net_ctx;
    iot_error_t err = IOT_ERROR_NET_SNTP;
    uint32_t tx_secs;
    int len;

    net_ctx = port_net_init();
    if (net_ctx == NULL) {
        return IOT_ERROR_MEM_ALLOC;
    }

    if (port_net_connect(net_ctx, (char *)server, SNTP_PORT, PORT_NET_PROTO_UDP, NULL) != PORT_NET_CONNECT_SUCCESS) {
        IOT_WARN("SNTP connect to %s failed", server);
        goto out;
    }

    if (port_net_write(net_ctx, pkt, SNTP_PACKET_SIZE) != SNTP_PACKET_SIZE) {
        IOT_WARN("SNTP request to %s failed", server);
        goto out;
    }

    if (port_net_read_poll(net_ctx, SNTP_RESPONSE_TIMEOUT_MS) <= 0) {
        IOT_WARN("SNTP response from %s timed out", server);
        goto out;
    }

    len = port_net_read(net_ctx, pkt, SNTP_PACKET_SIZE);
    if (len < SNTP_PACKET_SIZE) {
        IOT_WARN("SNTP short response from %s (%d)", server, len);
        goto out;
    }

    tx_secs = _sntp_be32(&pkt[SNTP_TX_TIMESTAMP_OFFSET]);
    if ((pkt[0] & SNTP_MODE_MASK) != SNTP_MODE_SERVER || (pkt[0] & SNTP_LI_MASK) == SNTP_LI_ALARM || pkt[1] == 0 ||
        pkt[1] > SNTP_STRATUM_MAX || tx_secs == 0) {
        IOT_WARN("SNTP invalid response from %s", server);
        goto out;
    }

    /* NTP 32bit seconds roll over in Feb 2036. A cleared MSB means era 1. */
    if (tx_secs & 0x80000000UL) {
        *epoch = (time_t)(tx_secs - SNTP_UNIX_OFFSET);
    } else {
        *epoch = (time_t)tx_secs + (time_t)SNTP_ERA1_UNIX_BASE;
    }
    err = IOT_ERROR_NONE;

out:
    port_net_close(net_ctx);
    port_net_free(net_ctx);
    return err;
}

iot_error_t iot_sntp_sync(void)
{
    size_t i;

    for (i = 0; i < sizeof(sntp_servers) / sizeof(sntp_servers[0]); i++) {
        time_t now = 0;

        if (_sntp_query(sntp_servers[i], &now) != IOT_ERROR_NONE) {
            continue;
        }

        IOT_INFO("SNTP time from %s : %lld", sntp_servers[i], (long long)now);
        return iot_bsp_system_set_time_in_sec(now);
    }

    IOT_ERROR("SNTP sync failed for all servers");
    return IOT_ERROR_NET_SNTP;
}

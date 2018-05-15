/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2018  Commend International GmbH. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

/*
 *  Address Conflict Detection (RFC 5227)
 *
 *  based on DHCP client library with GLib integration,
 *      Copyright (C) 2009-2014  Intel Corporation. All rights reserved.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

#include "connman.h"
#include <connman/acd.h>
#include <connman/log.h>
#include <connman/inet.h>
#include <glib.h>
#include "src/shared/arp.h"

enum acd_state {
	ACD_STATE_PROBE,
	ACD_STATE_ANNOUNCE,
	ACD_STATE_MONITOR,
	ACD_STATE_DEFEND,
};

struct acd_host {
	enum acd_state state;
	int ifindex;
	char *interface;
	uint8_t mac_address[6];
	uint32_t requested_ip; /* host byte order */

	bool listen_on;
	int listener_sockfd;
	unsigned int retry_times;
	unsigned int conflicts;
	guint timeout;
	guint listener_watch;

	acd_host_cb_t ipv4_available_cb;
	gpointer ipv4_available_data;
	acd_host_cb_t ipv4_lost_cb;
	gpointer ipv4_lost_data;
	acd_host_cb_t ipv4_conflict_cb;
	gpointer ipv4_conflict_data;
	acd_host_cb_t ipv4_max_conflicts_cb;
	gpointer ipv4_max_conflicts_data;
};

static int start_listening(struct acd_host *acd);
static void stop_listening(struct acd_host *acd);
static gboolean acd_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer acd_data);
static int acd_recv_arp_packet(struct acd_host *acd);
static void send_probe_packet(gpointer acd_data);
static gboolean acd_probe_timeout(gpointer acd_data);
static gboolean send_announce_packet(gpointer acd_data);
static gboolean acd_announce_timeout(gpointer acd_data);
static gboolean acd_defend_timeout(gpointer acd_data);

static void debug(struct acd_host *acd, const char *format, ...)
{
	char str[256];
	va_list ap;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		connman_info("ACD index %d: %s", acd->ifindex, str);

	va_end(ap);
}

struct acd_host *acd_host_new(int ifindex)
{
	struct acd_host *acd;

	if (ifindex < 0) {
		connman_error("Invalid interface index %d", ifindex);
		return NULL;
	}

	acd = g_try_new0(struct acd_host, 1);
	if (!acd) {
		connman_error("Could not allocate ACD data structure");
		return NULL;
	}

	acd->interface = connman_inet_ifname(ifindex);
	if (!acd->interface) {
		connman_error("Interface with index %d is not available", ifindex);
		goto error;
	}

	if (!connman_inet_is_ifup(ifindex)) {
		connman_error("Interface with index %d and name %s is down", ifindex,
				acd->interface);
		goto error;
	}

	__connman_inet_get_interface_mac_address(ifindex, acd->mac_address);

	acd->listener_sockfd = -1;
	acd->listen_on = false;
	acd->ifindex = ifindex;
	acd->listener_watch = 0;
	acd->retry_times = 0;

	acd->ipv4_available_cb = NULL;
	acd->ipv4_lost_cb = NULL;
	acd->ipv4_conflict_cb = NULL;
	acd->ipv4_max_conflicts_cb = NULL;

	return acd;

error:
	g_free(acd->interface);
	g_free(acd);
	return NULL;
}

static void remove_timeout(struct acd_host *acd)
{
	if (acd->timeout > 0)
		g_source_remove(acd->timeout);

	acd->timeout = 0;
}

static int start_listening(struct acd_host *acd)
{
	GIOChannel *listener_channel;
	int listener_sockfd;

	if (acd->listen_on)
		return 0;

	debug(acd, "start listening");

	listener_sockfd = arp_socket(acd->ifindex);
	if (listener_sockfd < 0)
		return -EIO;

	listener_channel = g_io_channel_unix_new(listener_sockfd);
	if (!listener_channel) {
		/* Failed to create listener channel */
		close(listener_sockfd);
		return -EIO;
	}

	acd->listen_on = true;
	acd->listener_sockfd = listener_sockfd;

	g_io_channel_set_close_on_unref(listener_channel, TRUE);
	acd->listener_watch =
			g_io_add_watch_full(listener_channel, G_PRIORITY_HIGH,
				G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						acd_listener_event, acd,
								NULL);
	g_io_channel_unref(listener_channel);

	return 0;
}

static void stop_listening(struct acd_host *acd)
{
	if (!acd->listen_on)
		return;

	if (acd->listener_watch > 0)
		g_source_remove(acd->listener_watch);
	acd->listen_on = FALSE;
	acd->listener_sockfd = -1;
	acd->listener_watch = 0;
}

static gboolean acd_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer acd_data)
{
	struct acd_host *acd = acd_data;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		acd->listener_watch = 0;
		return FALSE;
	}

	if (!acd->listen_on)
		return FALSE;

	acd_recv_arp_packet(acd);

	return TRUE;
}

static int acd_recv_arp_packet(struct acd_host *acd)
{
	(void) acd;
	return 0;
}

int acd_host_start(struct acd_host *acd, uint32_t ip)
{
	int err;
	err = start_listening(acd);
	if (err)
		return err;

	return 0;
}

void acd_host_stop(struct acd_host *acd)
{
	stop_listening(acd);
}

static void send_probe_packet(gpointer acd_data)
{
	guint timeout;
	struct acd_host *acd = acd_data;

	debug(acd, "sending ARP probe request");
	remove_timeout(acd);
	if (acd->retry_times == 1) {
		acd->state = ACD_STATE_PROBE;
		start_listening(acd);
	}
	arp_send_packet(acd->mac_address, 0,
			acd->requested_ip, acd->ifindex);

	if (acd->retry_times < PROBE_NUM) {
		/* Add a random timeout in range of PROBE_MIN to PROBE_MAX. */
		timeout = __connman_util_random_delay_ms(PROBE_MAX-PROBE_MIN);
		timeout += PROBE_MIN * 1000;
	} else
		timeout = ANNOUNCE_WAIT * 1000;

	acd->timeout = g_timeout_add_full(G_PRIORITY_HIGH,
						 timeout,
						 acd_probe_timeout,
						 acd,
						 NULL);
}

static gboolean acd_probe_timeout(gpointer acd_data)
{
	struct acd_host *acd = acd_data;

	acd->timeout = 0;

	debug(acd, "acd probe timeout (retries %d)", acd->retry_times);
	if (acd->retry_times == PROBE_NUM) {
		acd->state = ACD_STATE_ANNOUNCE;
		acd->retry_times = 1;

		send_announce_packet(acd);
		return FALSE;
	}

	acd->retry_times++;
	send_probe_packet(acd);

	return FALSE;
}

static gboolean send_announce_packet(gpointer acd_data)
{
	struct acd_host *acd = acd_data;

	debug(acd, "sending ACD announce request");

	arp_send_packet(acd->mac_address,
				acd->requested_ip,
				acd->requested_ip,
				acd->ifindex);

	remove_timeout(acd);

	if (acd->state == ACD_STATE_DEFEND)
		acd->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
						DEFEND_INTERVAL,
						acd_defend_timeout,
						acd,
						NULL);
	else
		acd->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
						ANNOUNCE_INTERVAL,
						acd_announce_timeout,
						acd,
						NULL);
	return TRUE;
}

static gboolean acd_announce_timeout(gpointer acd_data)
{
	(void) acd_data;

	return FALSE;
}

static gboolean acd_defend_timeout(gpointer acd_data)
{
	(void) acd_data;

	return FALSE;
}

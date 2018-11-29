/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 Helium Systems, Inc.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP   0x10000
#endif

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/technology.h>
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/inet.h>
#include <connman/rtnl.h>
#include <connman/log.h>
#include <connman/setting.h>

struct ppp_data {
	int index;
	unsigned flags;
	unsigned int watch;
	struct connman_network *network;
};

static int ppp_network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void ppp_network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static int ppp_network_connect(struct connman_network *network)
{
	DBG("network %p", network);

	connman_network_set_connected(network, true);

	return 0;
}

static int ppp_network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	connman_network_set_connected(network, false);

	return 0;
}

static struct connman_network_driver ppp_network_driver = {
	.name		= "cellular",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= ppp_network_probe,
	.remove		= ppp_network_remove,
	.connect	= ppp_network_connect,
	.disconnect	= ppp_network_disconnect,
};

static void add_network(struct connman_device *device,
			struct ppp_data *ppp)
{
	struct connman_network *network;
	int index;
	char *ifname;

	network = connman_network_create("carrier",
					CONNMAN_NETWORK_TYPE_CELLULAR);
	if (!network)
		return;

	index = connman_device_get_index(device);

	if (index < 0) {
		return;
	}

	connman_network_set_index(network, index);
	ifname = connman_inet_ifname(index);
	if (!ifname)
		return;

	connman_network_set_name(network, "Cellular");

	if (connman_device_add_network(device, network) < 0) {
		connman_network_unref(network);
		g_free(ifname);
		return;
	}

	connman_network_set_group(network, "modem");
	connman_network_set_ipv4_method(network, CONNMAN_IPCONFIG_METHOD_DHCP);
	connman_network_set_index(network, index);
	connman_network_set_connected(network, true);

	ppp->network = network;
	g_free(ifname);
}

static void remove_network(struct connman_device *device,
				struct ppp_data *ppp)
{
	if (!ppp->network)
		return;

	connman_device_remove_network(device, ppp->network);
	connman_network_unref(ppp->network);

	ppp->network = NULL;
}

static void ppp_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct ppp_data *ppp = connman_device_get_data(device);

	DBG("index %d flags %d change %d", ppp->index, flags, change);

	if ((ppp->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP) {
			DBG("power on");
			connman_device_set_powered(device, true);
		} else {
			DBG("power off");
			connman_device_set_powered(device, false);
		}
	}

	if ((ppp->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");
			add_network(device, ppp);
		} else {
			DBG("carrier off");
			remove_network(device, ppp);
		}
	}

	ppp->flags = flags;
}

static int modem_dev_probe(struct connman_device *device)
{
	struct ppp_data *ppp;

	DBG("device %p", device);

	ppp = g_try_new0(struct ppp_data, 1);
	if (!ppp)
		return -ENOMEM;

	connman_device_set_data(device, ppp);

	ppp->index = connman_device_get_index(device);
	ppp->flags = 0;

	ppp->watch = connman_rtnl_add_newlink_watch(ppp->index,
						ppp_newlink, device);

	return 0;
}

static void modem_dev_remove(struct connman_device *device)
{
	struct ppp_data *ppp = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);
	connman_rtnl_remove_watch(ppp->watch);
	remove_network(device, ppp);

	g_free(ppp);
}

static int modem_dev_enable(struct connman_device *device)
{
	struct ppp_data *ppp = connman_device_get_data(device);

	DBG("device %p", device);

	return connman_inet_ifup(ppp->index);
}

static int modem_dev_disable(struct connman_device *device)
{
	struct ppp_data *ppp = connman_device_get_data(device);

	DBG("device %p", device);

	return connman_inet_ifdown(ppp->index);
}

static struct connman_device_driver modem_dev_driver = {
	.name           = "modem",
	.type           = CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe          = modem_dev_probe,
	.remove         = modem_dev_remove,
	.enable         = modem_dev_enable,
	.disable        = modem_dev_disable,
};

static int cellular_tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void cellular_tech_remove(struct connman_technology *technology)
{
	DBG("");
}

static GList *ppp_interface_list = NULL;

static void cellular_tech_add_interface(struct connman_technology *technology,
			int index, const char *name, const char *ident)
{
	DBG("index %d name %s ident %s", index, name, ident);

	if (g_list_find(ppp_interface_list, GINT_TO_POINTER((int)index)))
		return;

	ppp_interface_list = g_list_prepend(ppp_interface_list,
					(GINT_TO_POINTER((int) index)));
}

static void cellular_tech_remove_interface(struct connman_technology *technology,
								int index)
{
	DBG("index %d", index);

	ppp_interface_list = g_list_remove(ppp_interface_list,
					GINT_TO_POINTER((int) index));
}

static struct connman_technology_driver cellular_tech_driver = {
	.name                   = "cellular",
	.type                   = CONNMAN_SERVICE_TYPE_CELLULAR,
	.probe                  = cellular_tech_probe,
	.remove                 = cellular_tech_remove,
	.add_interface          = cellular_tech_add_interface,
	.remove_interface       = cellular_tech_remove_interface,
};

static int pppd_init(void)
{
	int err;

	err = connman_technology_driver_register(&cellular_tech_driver);
	if (err < 0)
		return err;

	err = connman_network_driver_register(&ppp_network_driver);
	if (err < 0)
		return err;

	err = connman_device_driver_register(&modem_dev_driver);
	if (err < 0) {
		connman_network_driver_unregister(&ppp_network_driver);
		return err;
	}

	return 0;
}

static void pppd_exit(void)
{
	connman_technology_driver_unregister(&cellular_tech_driver);
	connman_network_driver_unregister(&ppp_network_driver);
	connman_device_driver_unregister(&modem_dev_driver);
}

CONNMAN_PLUGIN_DEFINE(pppd, "pppd telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, pppd_init, pppd_exit)

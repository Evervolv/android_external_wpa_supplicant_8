/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <binder/IServiceManager.h>

#include "binder_manager.h"
#include "wpa_supplicant_binder/binder_constants.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
}

namespace wpa_supplicant_binder {

BinderManager *BinderManager::instance_ = NULL;

BinderManager *BinderManager::getInstance()
{
	if (!instance_)
		instance_ = new BinderManager();
	return instance_;
}

void BinderManager::destroyInstance()
{
	if (instance_)
		delete instance_;
	instance_ = NULL;
}

int BinderManager::registerBinderService(struct wpa_global *global)
{
	// Create the main binder service object and register with system
	// ServiceManager.
	supplicant_object_ = new Supplicant(global);
	android::String16 service_name(binder_constants::kServiceName);
	android::defaultServiceManager()->addService(
	    service_name, android::IInterface::asBinder(supplicant_object_));
	return 0;
}

/**
 * Register an interface to binder manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::registerInterface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return 1;

	// Using the corresponding ifname as key to our object map.
	const std::string ifname(wpa_s->ifname);

	// Return failure if we already have an object for that |ifname|.
	if (iface_object_map_.find(ifname) != iface_object_map_.end())
		return 1;

	iface_object_map_[ifname] = new Iface(wpa_s->global, wpa_s->ifname);
	if (!iface_object_map_[ifname].get())
		return 1;

	return 0;
}

/**
 * Unregister an interface from binder manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::unregisterInterface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return 1;

	const std::string ifname(wpa_s->ifname);
	if (iface_object_map_.find(ifname) == iface_object_map_.end())
		return 1;

	/* Delete the corresponding iface object from our map. */
	iface_object_map_.erase(ifname);
	return 0;
}

/**
 * Register a network to binder manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the network is added.
 * @param ssid |wpa_ssid| struct corresponding to the network being added.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::registerNetwork(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !ssid)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(wpa_s->ifname, ssid->id);

	if (network_object_map_.find(network_key) != network_object_map_.end())
		return 1;

	network_object_map_[network_key] =
	    new Network(wpa_s->global, wpa_s->ifname, ssid->id);
	if (!network_object_map_[network_key].get())
		return 1;

	return 0;
}

/**
 * Unregister a network from binder manager.
 *
 * @param wpa_s |wpa_supplicant| struct corresponding to the interface on which
 * the network is added.
 * @param ssid |wpa_ssid| struct corresponding to the network being added.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::unregisterNetwork(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !ssid)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(wpa_s->ifname, ssid->id);

	if (network_object_map_.find(network_key) == network_object_map_.end())
		return 1;

	/* Delete the corresponding network object from our map. */
	network_object_map_.erase(network_key);
	return 0;
}

/**
 * Retrieve the |IIface| binder object reference using the provided ifname.
 *
 * @param ifname Name of the corresponding interface.
 * @param iface_object Binder reference corresponding to the iface.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::getIfaceBinderObjectByIfname(
    const std::string &ifname,
    android::sp<fi::w1::wpa_supplicant::IIface> *iface_object)
{
	if (ifname.empty() || !iface_object)
		return 1;

	if (iface_object_map_.find(ifname) == iface_object_map_.end())
		return 1;

	*iface_object = iface_object_map_[ifname];
	return 0;
}

/**
 * Retrieve the |INetwork| binder object reference using the provided ifname
 * and network_id.
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 * @param network_object Binder reference corresponding to the network.
 *
 * @return 0 on success, 1 on failure.
 */
int BinderManager::getNetworkBinderObjectByIfnameAndNetworkId(
    const std::string &ifname, int network_id,
    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object)
{
	if (ifname.empty() || network_id < 0 || !network_object)
		return 1;

	// Generate the key to be used to lookup the network.
	const std::string network_key =
	    getNetworkObjectMapKey(ifname, network_id);

	if (network_object_map_.find(network_key) == network_object_map_.end())
		return 1;

	*network_object = network_object_map_[network_key];
	return 0;
}

/**
 * Creates a unique key for the network using the provided |ifname| and
 * |network_id| to be used
 * in the internal map of |INetwork| objects.
 * This is of the form |ifname|_|network_id|. For ex: "wlan0_1".
 *
 * @param ifname Name of the corresponding interface.
 * @param network_id ID of the corresponding network.
 */
const std::string
BinderManager::getNetworkObjectMapKey(const std::string &ifname, int network_id)
{
	return ifname + "_" + std::to_string(network_id);
}
} // namespace wpa_supplicant_binder

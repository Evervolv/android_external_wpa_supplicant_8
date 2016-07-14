/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "binder_manager.h"
#include "iface.h"

namespace wpa_supplicant_binder {

Iface::Iface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname)
{
}

android::binder::Status Iface::GetName(std::string *iface_name_out)
{
	// We could directly return the name we hold, but let's verify
	// if the underlying iface still exists.
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_INVALID,
		    "wpa_supplicant does not control this interface.");
	}

	*iface_name_out = ifname_;
	return android::binder::Status::ok();
}

android::binder::Status Iface::AddNetwork(
    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object_out)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_INVALID,
		    "wpa_supplicant does not control this interface.");
	}

	struct wpa_ssid *ssid = wpa_config_add_network(wpa_s->conf);
	if (!ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "wpa_supplicant couldn't add this network.");
	}

	// This sequence of steps after network addition is following what is
	// currently being done in |ctrl_iface.c| & |dbus_new_handlers|.
	// Notify the control interfaces about the network addition.
	wpas_notify_network_added(wpa_s, ssid);
	// Set the new network to be disabled.
	ssid->disabled = 1;
	// Set defaults for the new network.
	wpa_config_set_network_defaults(ssid);

	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->getNetworkBinderObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, network_object_out)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::RemoveNetwork(int network_id)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_INVALID,
		    "wpa_supplicant does not control this interface.");
	}

	struct wpa_ssid *ssid = wpa_config_get_network(wpa_s->conf, network_id);
	if (!ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_UNKNOWN,
		    "wpa_supplicant does not control this network.");
	}
	if (wpa_config_remove_network(wpa_s->conf, network_id)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant couldn't remove this network.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::GetNetwork(
    int network_id,
    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object_out)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_INVALID,
		    "wpa_supplicant does not control this interface.");
	}

	struct wpa_ssid *ssid = wpa_config_get_network(wpa_s->conf, network_id);
	if (!ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_UNKNOWN,
		    "wpa_supplicant does not control this network.");
	}

	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->getNetworkBinderObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, network_object_out)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::RegisterCallback(
    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback> &callback)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_INVALID,
		    "wpa_supplicant does not control this interface.");
	}
	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->addIfaceCallbackBinderObject(ifname_, callback)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

/**
 * Retrieve the underlying |wpa_supplicant| struct pointer for
 * this iface.
 * If the underlying iface is removed, then all RPC method calls
 * on this object will return failure.
 */
wpa_supplicant *Iface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
}

} // namespace wpa_supplicant_binder

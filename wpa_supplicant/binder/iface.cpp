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

#define RETURN_IF_IFACE_INVALID(wpa_s)                                  \
	{                                                               \
		if (!wpa_s) {                                           \
			return android::binder::Status::                \
			    fromServiceSpecificError(                   \
				ERROR_IFACE_INVALID,                    \
				"wpa_supplicant does not control this " \
				"interface.");                          \
		}                                                       \
	}  // #define RETURN_IF_IFACE_INVALID(wpa_s)

Iface::Iface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname)
{
}

android::binder::Status Iface::GetName(std::string *iface_name_out)
{
	// We could directly return the name we hold, but let's verify
	// if the underlying iface still exists.
	RETURN_IF_IFACE_INVALID(retrieveIfacePtr());
	*iface_name_out = ifname_;
	return android::binder::Status::ok();
}

android::binder::Status Iface::AddNetwork(
    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object_out)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	struct wpa_ssid *ssid = wpa_supplicant_add_network(wpa_s);
	if (!ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "wpa_supplicant couldn't add this network.");
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

android::binder::Status Iface::RemoveNetwork(int network_id)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	int result = wpa_supplicant_remove_network(wpa_s, network_id);
	if (result == -1) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_UNKNOWN,
		    "wpa_supplicant does not control this network.");
	}

	if (result == -2) {
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
	RETURN_IF_IFACE_INVALID(wpa_s);

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
	RETURN_IF_IFACE_INVALID(wpa_s);

	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->addIfaceCallbackBinderObject(ifname_, callback)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::Reassociate()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_DISABLED);
	}
	wpas_request_connection(wpa_s);
	return android::binder::Status::ok();
}

android::binder::Status Iface::Reconnect()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_DISABLED);
	}
	if (!wpa_s->disconnected) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_NOT_DISCONNECTED);
	}
	wpas_request_connection(wpa_s);
	return android::binder::Status::ok();
}

android::binder::Status Iface::Disconnect()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_DISABLED);
	}
	wpas_request_disconnection(wpa_s);
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
}  // namespace wpa_supplicant_binder

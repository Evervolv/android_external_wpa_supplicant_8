/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "binder_manager.h"
#include "network.h"

namespace wpa_supplicant_binder {

Network::Network(
    struct wpa_global *wpa_global, const char ifname[], int network_id)
    : wpa_global_(wpa_global), ifname_(ifname), network_id_(network_id)
{
}

android::binder::Status Network::GetId(int *network_id_out)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (!wpa_ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_INVALID,
		    "wpa_supplicant does not control this network.");
	}

	*network_id_out = network_id_;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetInterfaceName(std::string *ifname_out)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (!wpa_ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_INVALID,
		    "wpa_supplicant does not control this network.");
	}

	*ifname_out = ifname_;
	return android::binder::Status::ok();
}

android::binder::Status Network::RegisterCallback(
    const android::sp<fi::w1::wpa_supplicant::INetworkCallback> &callback)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (!wpa_ssid) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_NETWORK_INVALID,
		    "wpa_supplicant does not control this network.");
	}
	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->addNetworkCallbackBinderObject(
		ifname_, network_id_, callback)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

/**
 * Retrieve the underlying |wpa_ssid| struct pointer for
 * this network.
 * If the underlying network is removed or the interface this network belong to
 * is removed, all RPC method calls on this object will return failure.
 */
struct wpa_ssid *Network::retrieveNetworkPtr()
{
	wpa_supplicant *wpa_s = wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
	if (!wpa_s)
		return nullptr;
	return wpa_config_get_network(wpa_s->conf, network_id_);
}

} // namespace wpa_supplicant_binder

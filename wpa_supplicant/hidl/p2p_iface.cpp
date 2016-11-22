/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "hidl_manager.h"
#include "hidl_return_macros.h"
#include "p2p_iface.h"

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

P2pIface::P2pIface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname)
{
}

Return<void> P2pIface::getName(getName_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID, ifname_);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, ifname_);
}

Return<void> P2pIface::getType(getType_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID,
		    IfaceType::STA);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, IfaceType::STA);
}

Return<void> P2pIface::addNetwork(addNetwork_cb _hidl_cb)
{
	android::sp<ISupplicantP2pNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID, network);
	}

	struct wpa_ssid *ssid = wpa_supplicant_add_network(wpa_s);
	if (!ssid) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, network);
	}

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getP2pNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, network);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, network);
}

Return<void> P2pIface::removeNetwork(uint32_t id, removeNetwork_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	int result = wpa_supplicant_remove_network(wpa_s, id);
	if (result == -1) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN);
	}

	if (result != 0) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> P2pIface::getNetwork(uint32_t id, getNetwork_cb _hidl_cb)
{
	android::sp<ISupplicantP2pNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID, network);
	}

	struct wpa_ssid *ssid = wpa_config_get_network(wpa_s->conf, id);
	if (!ssid) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN, network);
	}

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getP2pNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, network);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, network);
}

Return<void> P2pIface::listNetworks(listNetworks_cb _hidl_cb)
{
	std::vector<uint32_t> network_ids;

	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID, network_ids);
	}

	for (struct wpa_ssid *wpa_ssid = wpa_s->conf->ssid; wpa_ssid;
	     wpa_ssid = wpa_ssid->next) {
		network_ids.emplace_back(wpa_ssid->id);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, network_ids);
}

Return<void> P2pIface::registerCallback(
    const sp<ISupplicantP2pIfaceCallback> &callback,
    registerCallback_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveP2pIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addP2pIfaceCallbackHidlObject(ifname_, callback)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this iface.
 * If the underlying iface is removed, then all RPC method calls on this object
 * will return failure.
 */
wpa_supplicant *P2pIface::retrieveP2pIfacePtr()
{
	return wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

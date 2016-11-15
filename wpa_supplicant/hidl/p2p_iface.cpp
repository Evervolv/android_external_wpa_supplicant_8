/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "hidl_manager.h"
#include "hidl_return_util.h"
#include "p2p_iface.h"

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {
using hidl_return_util::validateAndCall;

P2pIface::P2pIface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname), is_valid_(true)
{
}

void P2pIface::invalidate() { is_valid_ = false; }
bool P2pIface::isValid()
{
	return (is_valid_ && (retrieveIfacePtr() != nullptr));
}
Return<void> P2pIface::getName(getName_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getNameInternal, _hidl_cb);
}

Return<void> P2pIface::getType(getType_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getTypeInternal, _hidl_cb);
}

Return<void> P2pIface::addNetwork(addNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::addNetworkInternal, _hidl_cb);
}

Return<void> P2pIface::removeNetwork(
    SupplicantNetworkId id, removeNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::removeNetworkInternal, _hidl_cb, id);
}

Return<void> P2pIface::getNetwork(
    SupplicantNetworkId id, getNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getNetworkInternal, _hidl_cb, id);
}

Return<void> P2pIface::listNetworks(listNetworks_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::listNetworksInternal, _hidl_cb);
}

Return<void> P2pIface::registerCallback(
    const sp<ISupplicantP2pIfaceCallback> &callback,
    registerCallback_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::registerCallbackInternal, _hidl_cb, callback);
}

std::pair<SupplicantStatus, std::string> P2pIface::getNameInternal()
{
	return {{SupplicantStatusCode::SUCCESS, ""}, ifname_};
}

std::pair<SupplicantStatus, IfaceType> P2pIface::getTypeInternal()
{
	return {{SupplicantStatusCode::SUCCESS, ""}, IfaceType::P2P};
}

std::pair<SupplicantStatus, sp<ISupplicantP2pNetwork>>
P2pIface::addNetworkInternal()
{
	android::sp<ISupplicantP2pNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *ssid = wpa_supplicant_add_network(wpa_s);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getP2pNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, network};
}

SupplicantStatus P2pIface::removeNetworkInternal(SupplicantNetworkId id)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	int result = wpa_supplicant_remove_network(wpa_s, id);
	if (result == -1) {
		return {SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN, ""};
	}
	if (result != 0) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, sp<ISupplicantP2pNetwork>>
P2pIface::getNetworkInternal(SupplicantNetworkId id)
{
	android::sp<ISupplicantP2pNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *ssid = wpa_config_get_network(wpa_s->conf, id);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN, ""},
			network};
	}
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getP2pNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, network};
}

std::pair<SupplicantStatus, std::vector<SupplicantNetworkId>>
P2pIface::listNetworksInternal()
{
	std::vector<SupplicantNetworkId> network_ids;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	for (struct wpa_ssid *wpa_ssid = wpa_s->conf->ssid; wpa_ssid;
	     wpa_ssid = wpa_ssid->next) {
		network_ids.emplace_back(wpa_ssid->id);
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, std::move(network_ids)};
}

SupplicantStatus P2pIface::registerCallbackInternal(
    const sp<ISupplicantP2pIfaceCallback> &callback)
{
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addP2pIfaceCallbackHidlObject(ifname_, callback)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this iface.
 * If the underlying iface is removed, then all RPC method calls on this object
 * will return failure.
 */
wpa_supplicant *P2pIface::retrieveIfacePtr()
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

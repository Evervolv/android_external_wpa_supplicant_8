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
#include "iface.h"

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

Iface::Iface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname)
{
}

Return<void> Iface::getName(getName_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_INVALID, ifname_);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, ifname_);
}

Return<void> Iface::addNetwork(addNetwork_cb _hidl_cb)
{
	android::sp<ISupplicantNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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
	    hidl_manager->getNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, network);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, network);
}

Return<void> Iface::removeNetwork(uint32_t id, removeNetwork_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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

Return<void> Iface::getNetwork(uint32_t id, getNetwork_cb _hidl_cb)
{
	android::sp<ISupplicantNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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
	    hidl_manager->getNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, network);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, network);
}

Return<void> Iface::listNetworks(listNetworks_cb _hidl_cb)
{
	std::vector<uint32_t> network_ids;

	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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

Return<void> Iface::registerCallback(
    const sp<ISupplicantIfaceCallback> &callback, registerCallback_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addIfaceCallbackHidlObject(ifname_, callback)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::reassociate(reassociate_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_DISABLED);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::reconnect(reconnect_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_DISABLED);
	}
	if (!wpa_s->disconnected) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_NOT_DISCONNECTED);
	}

	wpas_request_connection(wpa_s);

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::disconnect(disconnect_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_DISABLED);
	}

	wpas_request_disconnection(wpa_s);

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::setPowerSave(bool enable, setPowerSave_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (wpa_drv_set_p2p_powersave(wpa_s, enable, -1, -1)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::initiateTdlsDiscover(
    const hidl_array<uint8_t, 6 /* 6 */> &mac_address,
    initiateTdlsDiscover_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (!mac_address.data()) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_ARGS_INVALID);
	}

	int ret;
	const u8 *peer = mac_address.data();
	if (wpa_tdls_is_external_setup(wpa_s->wpa)) {
		ret = wpa_tdls_send_discovery_request(wpa_s->wpa, peer);
	} else {
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_DISCOVERY_REQ, peer);
	}
	if (ret) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::initiateTdlsSetup(
    const hidl_array<uint8_t, 6 /* 6 */> &mac_address,
    initiateTdlsSetup_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (!mac_address.data()) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_ARGS_INVALID);
	}

	int ret;
	const u8 *peer = mac_address.data();
	if (wpa_tdls_is_external_setup(wpa_s->wpa) &&
	    !(wpa_s->conf->tdls_external_control)) {
		wpa_tdls_remove(wpa_s->wpa, peer);
		ret = wpa_tdls_start(wpa_s->wpa, peer);
	} else {
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_SETUP, peer);
	}
	if (ret) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Iface::initiateTdlsTeardown(
    const hidl_array<uint8_t, 6 /* 6 */> &mac_address,
    initiateTdlsTeardown_cb _hidl_cb)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_INVALID);
	}

	if (!mac_address.data()) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_ARGS_INVALID);
	}

	int ret;
	const u8 *peer = mac_address.data();
	if (wpa_tdls_is_external_setup(wpa_s->wpa) &&
	    !(wpa_s->conf->tdls_external_control)) {
		ret = wpa_tdls_teardown_link(
		    wpa_s->wpa, peer, WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED);
	} else {
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_TEARDOWN, peer);
	}

	if (ret) {
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
wpa_supplicant *Iface::retrieveIfacePtr()
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

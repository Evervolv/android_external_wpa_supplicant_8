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

android::binder::Status Iface::SetPowerSave(bool enable)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);
	if (wpa_drv_set_p2p_powersave(wpa_s, enable, -1, -1)) {
		const std::string error_msg = "Failed setting power save mode" +
					      std::to_string(enable) + ".";
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, error_msg.c_str());
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::InitiateTDLSDiscover(
    const std::vector<uint8_t> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (mac_address.size() != MAC_ADDRESS_LEN) {
		const std::string error_msg =
		    "Invalid MAC address value length: " +
		    std::to_string(mac_address.size()) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	int ret;
	const u8 *peer = mac_address.data();
	if (wpa_tdls_is_external_setup(wpa_s->wpa)) {
		ret = wpa_tdls_send_discovery_request(wpa_s->wpa, peer);
	} else {
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_DISCOVERY_REQ, peer);
	}
	if (ret) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Failed to initiate TDLS Discover.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::InitiateTDLSSetup(
    const std::vector<uint8_t> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (mac_address.size() != MAC_ADDRESS_LEN) {
		const std::string error_msg =
		    "Invalid MAC address value length: " +
		    std::to_string(mac_address.size()) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
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
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Failed to initiate TDLS Setup.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Iface::InitiateTDLSTeardown(
    const std::vector<uint8_t> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	RETURN_IF_IFACE_INVALID(wpa_s);

	if (mac_address.size() != MAC_ADDRESS_LEN) {
		const std::string error_msg =
		    "Invalid MAC address value length: " +
		    std::to_string(mac_address.size()) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
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
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Failed to initiate TDLS Teardown.");
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
}  // namespace wpa_supplicant_binder

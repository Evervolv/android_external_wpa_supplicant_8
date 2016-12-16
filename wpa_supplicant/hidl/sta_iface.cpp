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
#include "sta_iface.h"

extern "C" {
#include "gas_query.h"
#include "interworking.h"
#include "hs20_supplicant.h"
}

namespace {
constexpr uint32_t kMaxAnqpElems = 100;
}  // namespace

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {
using hidl_return_util::validateAndCall;

StaIface::StaIface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname), is_valid_(true)
{
}

void StaIface::invalidate() { is_valid_ = false; }
bool StaIface::isValid()
{
	return (is_valid_ && (retrieveIfacePtr() != nullptr));
}

Return<void> StaIface::getName(getName_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::getNameInternal, _hidl_cb);
}

Return<void> StaIface::getType(getType_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::getTypeInternal, _hidl_cb);
}

Return<void> StaIface::addNetwork(addNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::addNetworkInternal, _hidl_cb);
}

Return<void> StaIface::removeNetwork(
    SupplicantNetworkId id, removeNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::removeNetworkInternal, _hidl_cb, id);
}

Return<void> StaIface::getNetwork(
    SupplicantNetworkId id, getNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::getNetworkInternal, _hidl_cb, id);
}

Return<void> StaIface::listNetworks(listNetworks_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::listNetworksInternal, _hidl_cb);
}

Return<void> StaIface::registerCallback(
    const sp<ISupplicantStaIfaceCallback> &callback,
    registerCallback_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::registerCallbackInternal, _hidl_cb, callback);
}

Return<void> StaIface::reassociate(reassociate_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::reassociateInternal, _hidl_cb);
}

Return<void> StaIface::reconnect(reconnect_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::reconnectInternal, _hidl_cb);
}

Return<void> StaIface::disconnect(disconnect_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::disconnectInternal, _hidl_cb);
}

Return<void> StaIface::setPowerSave(bool enable, setPowerSave_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::setPowerSaveInternal, _hidl_cb, enable);
}

Return<void> StaIface::initiateTdlsDiscover(
    const hidl_array<uint8_t, 6> &mac_address, initiateTdlsDiscover_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::initiateTdlsDiscoverInternal, _hidl_cb, mac_address);
}

Return<void> StaIface::initiateTdlsSetup(
    const hidl_array<uint8_t, 6> &mac_address, initiateTdlsSetup_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::initiateTdlsSetupInternal, _hidl_cb, mac_address);
}

Return<void> StaIface::initiateTdlsTeardown(
    const hidl_array<uint8_t, 6> &mac_address, initiateTdlsTeardown_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::initiateTdlsTeardownInternal, _hidl_cb, mac_address);
}
Return<void> StaIface::initiateAnqpQuery(
    const hidl_array<uint8_t, 6> &mac_address,
    const hidl_vec<ISupplicantStaIface::AnqpInfoId> &info_elements,
    const hidl_vec<ISupplicantStaIface::Hs20AnqpSubtypes> &sub_types,
    initiateAnqpQuery_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::initiateAnqpQueryInternal, _hidl_cb, mac_address,
	    info_elements, sub_types);
}

Return<void> StaIface::initiateHs20IconQuery(
    const hidl_array<uint8_t, 6> &mac_address, const hidl_string &file_name,
    initiateHs20IconQuery_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::initiateHs20IconQueryInternal, _hidl_cb, mac_address,
	    file_name);
}

std::pair<SupplicantStatus, std::string> StaIface::getNameInternal()
{
	return {{SupplicantStatusCode::SUCCESS, ""}, ifname_};
}

std::pair<SupplicantStatus, IfaceType> StaIface::getTypeInternal()
{
	return {{SupplicantStatusCode::SUCCESS, ""}, IfaceType::STA};
}

std::pair<SupplicantStatus, sp<ISupplicantNetwork>>
StaIface::addNetworkInternal()
{
	android::sp<ISupplicantStaNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *ssid = wpa_supplicant_add_network(wpa_s);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getStaNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, network};
}

SupplicantStatus StaIface::removeNetworkInternal(SupplicantNetworkId id)
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

std::pair<SupplicantStatus, sp<ISupplicantNetwork>>
StaIface::getNetworkInternal(SupplicantNetworkId id)
{
	android::sp<ISupplicantStaNetwork> network;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *ssid = wpa_config_get_network(wpa_s->conf, id);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN, ""},
			network};
	}
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getStaNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, network};
}

std::pair<SupplicantStatus, std::vector<SupplicantNetworkId>>
StaIface::listNetworksInternal()
{
	std::vector<SupplicantNetworkId> network_ids;
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	for (struct wpa_ssid *wpa_ssid = wpa_s->conf->ssid; wpa_ssid;
	     wpa_ssid = wpa_ssid->next) {
		network_ids.emplace_back(wpa_ssid->id);
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, std::move(network_ids)};
}

SupplicantStatus StaIface::registerCallbackInternal(
    const sp<ISupplicantStaIfaceCallback> &callback)
{
	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addStaIfaceCallbackHidlObject(ifname_, callback)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::reassociateInternal()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return {SupplicantStatusCode::FAILURE_IFACE_DISABLED, ""};
	}
	wpas_request_connection(wpa_s);
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::reconnectInternal()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return {SupplicantStatusCode::FAILURE_IFACE_DISABLED, ""};
	}
	if (!wpa_s->disconnected) {
		return {SupplicantStatusCode::FAILURE_IFACE_NOT_DISCONNECTED,
			""};
	}
	wpas_request_connection(wpa_s);
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::disconnectInternal()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return {SupplicantStatusCode::FAILURE_IFACE_DISABLED, ""};
	}
	wpas_request_disconnection(wpa_s);
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::setPowerSaveInternal(bool enable)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
		return {SupplicantStatusCode::FAILURE_IFACE_DISABLED, ""};
	}
	if (wpa_drv_set_p2p_powersave(wpa_s, enable, -1, -1)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::initiateTdlsDiscoverInternal(
    const std::array<uint8_t, 6> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	int ret;
	const u8 *peer = mac_address.data();
	if (wpa_tdls_is_external_setup(wpa_s->wpa)) {
		ret = wpa_tdls_send_discovery_request(wpa_s->wpa, peer);
	} else {
		ret = wpa_drv_tdls_oper(wpa_s, TDLS_DISCOVERY_REQ, peer);
	}
	if (ret) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::initiateTdlsSetupInternal(
    const std::array<uint8_t, 6> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::initiateTdlsTeardownInternal(
    const std::array<uint8_t, 6> &mac_address)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
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
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::initiateAnqpQueryInternal(
    const std::array<uint8_t, 6> &mac_address,
    const std::vector<ISupplicantStaIface::AnqpInfoId> &info_elements,
    const std::vector<ISupplicantStaIface::Hs20AnqpSubtypes> &sub_types)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (info_elements.size() > kMaxAnqpElems) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	uint16_t *info_elems_buf = static_cast<uint16_t *>(
	    os_malloc(sizeof(uint16_t) * info_elements.size()));
	if (!info_elems_buf) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	uint32_t num_info_elems = 0;
	for (const auto &info_element : info_elements) {
		info_elems_buf[num_info_elems++] =
		    static_cast<std::underlying_type<
			ISupplicantStaIface::AnqpInfoId>::type>(info_element);
	}
	uint32_t sub_types_bitmask = 0;
	for (const auto &type : sub_types) {
		sub_types_bitmask |= BIT(
		    static_cast<std::underlying_type<
			ISupplicantStaIface::Hs20AnqpSubtypes>::type>(type));
	}
	if (anqp_send_req(
		wpa_s, mac_address.data(), info_elems_buf, num_info_elems,
		sub_types_bitmask, false)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus StaIface::initiateHs20IconQueryInternal(
    const std::array<uint8_t, 6> &mac_address, const std::string &file_name)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	wpa_s->fetch_osu_icon_in_progress = 0;
	if (hs20_anqp_send_req(
		wpa_s, mac_address.data(), BIT(HS20_STYPE_ICON_REQUEST),
		reinterpret_cast<const uint8_t *>(file_name.c_str()),
		file_name.size(), true)) {
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
wpa_supplicant *StaIface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(wpa_global_, ifname_.c_str());
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

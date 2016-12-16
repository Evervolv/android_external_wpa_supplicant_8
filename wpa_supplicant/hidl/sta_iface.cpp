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
constexpr char kGetMacAddress[] = "MACADDR";
constexpr char kStartRxFilter[] = "RXFILTER-START";
constexpr char kStopRxFilter[] = "RXFILTER-STOP";
constexpr char kAddRxFilter[] = "RXFILTER-ADD";
constexpr char kRemoveRxFilter[] = "RXFILTER-REMOVE";
constexpr char kSetBtCoexistenceMode[] = "BTCOEXMODE";
constexpr char kSetBtCoexistenceScanStart[] = "BTCOEXSCAN-START";
constexpr char kSetBtCoexistenceScanStop[] = "BTCOEXSCAN-STOP";
constexpr char kSetSupendModeEnabled[] = "SETSUSPENDMODE 1";
constexpr char kSetSupendModeDisabled[] = "SETSUSPENDMODE 0";
constexpr char kSetCountryCode[] = "COUNTRY ";

using android::hardware::wifi::supplicant::V1_0::ISupplicantStaIface;
using android::hardware::wifi::supplicant::V1_0::SupplicantStatus;
using android::hardware::wifi::supplicant::V1_0::SupplicantStatusCode;

uint8_t convertHidlRxFilterTypeToInternal(
    ISupplicantStaIface::RxFilterType type)
{
	switch (type) {
	case ISupplicantStaIface::RxFilterType::V4_MULTICAST:
		return 2;
	case ISupplicantStaIface::RxFilterType::V6_MULTICAST:
		return 3;
	};
	WPA_ASSERT(false);
}

uint8_t convertHidlBtCoexModeToInternal(
    ISupplicantStaIface::BtCoexistenceMode mode)
{
	switch (mode) {
	case ISupplicantStaIface::BtCoexistenceMode::ENABLED:
		return 0;
	case ISupplicantStaIface::BtCoexistenceMode::DISABLED:
		return 1;
	case ISupplicantStaIface::BtCoexistenceMode::SENSE:
		return 2;
	};
	WPA_ASSERT(false);
}

SupplicantStatus doZeroArgDriverCommand(
    struct wpa_supplicant *wpa_s, const char *cmd)
{
	std::vector<char> cmd_vec(cmd, cmd + strlen(cmd) + 1);
	char driver_cmd_reply_buf[4096] = {};
	if (wpa_drv_driver_cmd(
		wpa_s, cmd_vec.data(), driver_cmd_reply_buf,
		sizeof(driver_cmd_reply_buf))) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus doOneArgDriverCommand(
    struct wpa_supplicant *wpa_s, const char *cmd, uint8_t arg)
{
	std::string cmd_str = std::string(cmd) + " " + std::to_string(arg);
	return doZeroArgDriverCommand(wpa_s, cmd_str.c_str());
}

SupplicantStatus doOneArgDriverCommand(
    struct wpa_supplicant *wpa_s, const char *cmd, const std::string &arg)
{
	std::string cmd_str = std::string(cmd) + " " + arg;
	return doZeroArgDriverCommand(wpa_s, cmd_str.c_str());
}
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

Return<void> StaIface::getMacAddress(getMacAddress_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::getMacAddressInternal, _hidl_cb);
}

Return<void> StaIface::startRxFilter(startRxFilter_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::startRxFilterInternal, _hidl_cb);
}

Return<void> StaIface::stopRxFilter(stopRxFilter_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::stopRxFilterInternal, _hidl_cb);
}

Return<void> StaIface::addRxFilter(
    ISupplicantStaIface::RxFilterType type, addRxFilter_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::addRxFilterInternal, _hidl_cb, type);
}

Return<void> StaIface::removeRxFilter(
    ISupplicantStaIface::RxFilterType type, removeRxFilter_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::removeRxFilterInternal, _hidl_cb, type);
}

Return<void> StaIface::setBtCoexistenceMode(
    ISupplicantStaIface::BtCoexistenceMode mode,
    setBtCoexistenceMode_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::setBtCoexistenceModeInternal, _hidl_cb, mode);
}

Return<void> StaIface::setBtCoexistenceScanModeEnabled(
    bool enable, setBtCoexistenceScanModeEnabled_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::setBtCoexistenceScanModeEnabledInternal, _hidl_cb,
	    enable);
}

Return<void> StaIface::setSuspendModeEnabled(
    bool enable, setSuspendModeEnabled_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::setSuspendModeEnabledInternal, _hidl_cb, enable);
}

Return<void> StaIface::setCountryCode(
    const hidl_array<int8_t, 2> &code, setCountryCode_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &StaIface::setCountryCodeInternal, _hidl_cb, code);
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

std::pair<SupplicantStatus, std::array<uint8_t, 6>>
StaIface::getMacAddressInternal()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	std::vector<char> cmd(
	    kGetMacAddress, kGetMacAddress + sizeof(kGetMacAddress));
	char driver_cmd_reply_buf[4096] = {};
	int ret = wpa_drv_driver_cmd(
	    wpa_s, cmd.data(), driver_cmd_reply_buf,
	    sizeof(driver_cmd_reply_buf));
	// Reply is of the format: "Macaddr = XX:XX:XX:XX:XX:XX"
	std::string reply_str = driver_cmd_reply_buf;
	if (ret || reply_str.empty() ||
	    reply_str.find("=") == std::string::npos) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
	}
	// Remove all whitespace first and then split using the delimiter "=".
	reply_str.erase(
	    remove_if(reply_str.begin(), reply_str.end(), isspace),
	    reply_str.end());
	std::string mac_addr_str =
	    reply_str.substr(reply_str.find("=") + 1, reply_str.size());
	std::array<uint8_t, 6> mac_addr;
	if (hwaddr_aton(mac_addr_str.c_str(), mac_addr.data())) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, mac_addr};
}

SupplicantStatus StaIface::startRxFilterInternal()
{
	return doZeroArgDriverCommand(retrieveIfacePtr(), kStartRxFilter);
}

SupplicantStatus StaIface::stopRxFilterInternal()
{
	return doZeroArgDriverCommand(retrieveIfacePtr(), kStopRxFilter);
}

SupplicantStatus StaIface::addRxFilterInternal(
    ISupplicantStaIface::RxFilterType type)
{
	return doOneArgDriverCommand(
	    retrieveIfacePtr(), kAddRxFilter,
	    convertHidlRxFilterTypeToInternal(type));
}

SupplicantStatus StaIface::removeRxFilterInternal(
    ISupplicantStaIface::RxFilterType type)
{
	return doOneArgDriverCommand(
	    retrieveIfacePtr(), kRemoveRxFilter,
	    convertHidlRxFilterTypeToInternal(type));
}

SupplicantStatus StaIface::setBtCoexistenceModeInternal(
    ISupplicantStaIface::BtCoexistenceMode mode)
{
	return doOneArgDriverCommand(
	    retrieveIfacePtr(), kSetBtCoexistenceMode,
	    convertHidlBtCoexModeToInternal(mode));
}

SupplicantStatus StaIface::setBtCoexistenceScanModeEnabledInternal(bool enable)
{
	const char *cmd;
	if (enable) {
		cmd = kSetBtCoexistenceScanStart;
	} else {
		cmd = kSetBtCoexistenceScanStop;
	}
	return doZeroArgDriverCommand(retrieveIfacePtr(), cmd);
}

SupplicantStatus StaIface::setSuspendModeEnabledInternal(bool enable)
{
	const char *cmd;
	if (enable) {
		cmd = kSetSupendModeEnabled;
	} else {
		cmd = kSetSupendModeDisabled;
	}
	return doZeroArgDriverCommand(retrieveIfacePtr(), cmd);
}

SupplicantStatus StaIface::setCountryCodeInternal(
    const std::array<int8_t, 2> &code)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	SupplicantStatus status = doOneArgDriverCommand(
	    wpa_s, kSetCountryCode,
	    std::string(std::begin(code), std::end(code)));
	if (status.code != SupplicantStatusCode::SUCCESS) {
		return status;
	}
	struct p2p_data *p2p = wpa_s->global->p2p;
	if (p2p) {
		char country[3];
		country[0] = code[0];
		country[1] = code[1];
		country[2] = 0x04;
		p2p_set_country(p2p, country);
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

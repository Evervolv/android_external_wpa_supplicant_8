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

P2pIface::P2pIface(struct wpa_global* wpa_global, const char ifname[])
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
    const sp<ISupplicantP2pIfaceCallback>& callback,
    registerCallback_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::registerCallbackInternal, _hidl_cb, callback);
}

Return<void> P2pIface::getDeviceAddress(getDeviceAddress_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getDeviceAddressInternal, _hidl_cb);
}

Return<void> P2pIface::setSsidPostfix(
    const hidl_string& postfix, setSsidPostfix_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::setSsidPostfixInternal, _hidl_cb, postfix);
}

Return<void> P2pIface::setGroupIdle(
    uint32_t timeout_in_sec, setGroupIdle_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::setGroupIdleInternal, _hidl_cb, timeout_in_sec);
}

Return<void> P2pIface::setPowerSave(bool enable, setPowerSave_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::setPowerSaveInternal, _hidl_cb, enable);
}

Return<void> P2pIface::find(uint32_t timeout_in_sec, find_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::findInternal, _hidl_cb, timeout_in_sec);
}

Return<void> P2pIface::stopFind(stopFind_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::stopFindInternal, _hidl_cb);
}

Return<void> P2pIface::flush(flush_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::flushInternal, _hidl_cb);
}

Return<void> P2pIface::connect(
    const hidl_array<uint8_t, 6>& peer_address,
    ISupplicantP2pIface::WpsProvisionMethod provision_method,
    const hidl_vec<uint8_t>& pre_selected_pin, bool join_existing_group,
    bool persistent, uint32_t go_intent, connect_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::connectInternal, _hidl_cb, peer_address,
	    provision_method, pre_selected_pin, join_existing_group, persistent,
	    go_intent);
}

Return<void> P2pIface::cancelConnect(cancelConnect_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::cancelConnectInternal, _hidl_cb);
}

Return<void> P2pIface::provisionDiscovery(
    const hidl_array<uint8_t, 6>& peer_address,
    ISupplicantP2pIface::WpsProvisionMethod provision_method,
    provisionDiscovery_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::provisionDiscoveryInternal, _hidl_cb, peer_address,
	    provision_method);
}

Return<void> P2pIface::addGroup(
    bool persistent, uint32_t persistent_network_id, addGroup_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::addGroupInternal, _hidl_cb, persistent,
	    persistent_network_id);
}

Return<void> P2pIface::removeGroup(
    const hidl_string& group_ifname, removeGroup_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::removeGroupInternal, _hidl_cb, group_ifname);
}

Return<void> P2pIface::reject(
    const hidl_array<uint8_t, 6>& peer_address, reject_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::rejectInternal, _hidl_cb, peer_address);
}

Return<void> P2pIface::invite(
    const hidl_string& group_ifname,
    const hidl_array<uint8_t, 6>& go_device_address,
    const hidl_array<uint8_t, 6>& peer_address, invite_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::inviteInternal, _hidl_cb, go_device_address,
	    peer_address);
}

Return<void> P2pIface::reinvoke(
    uint32_t persistent_network_id, const hidl_array<uint8_t, 6>& peer_address,
    reinvoke_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::reinvokeInternal, _hidl_cb, persistent_network_id,
	    peer_address);
}

Return<void> P2pIface::configureExtListen(
    bool enable, uint32_t period_in_millis, uint32_t interval_in_millis,
    configureExtListen_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::configureExtListenInternal, _hidl_cb, enable,
	    period_in_millis, interval_in_millis);
}

Return<void> P2pIface::setListenChannel(
    uint32_t channel, uint32_t operating_class, setListenChannel_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::setListenChannelInternal, _hidl_cb, channel,
	    operating_class);
}

Return<void> P2pIface::getSsid(
    const hidl_array<uint8_t, 6>& peer_address, getSsid_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getSsidInternal, _hidl_cb, peer_address);
}

Return<void> P2pIface::getGroupCapability(
    const hidl_array<uint8_t, 6>& peer_address, getGroupCapability_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::getGroupCapabilityInternal, _hidl_cb, peer_address);
}

Return<void> P2pIface::addBonjourService(
    const hidl_vec<uint8_t>& query, const hidl_vec<uint8_t>& response,
    addBonjourService_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::addBonjourServiceInternal, _hidl_cb, query, response);
}

Return<void> P2pIface::removeBonjourService(
    const hidl_vec<uint8_t>& query, removeBonjourService_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::removeBonjourServiceInternal, _hidl_cb, query);
}

Return<void> P2pIface::addUpnpService(
    uint32_t version, const hidl_string& service_name,
    addUpnpService_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::addUpnpServiceInternal, _hidl_cb, version, service_name);
}

Return<void> P2pIface::removeUpnpService(
    uint32_t version, const hidl_string& service_name,
    removeUpnpService_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::removeUpnpServiceInternal, _hidl_cb, version,
	    service_name);
}

Return<void> P2pIface::flushServices(
    uint32_t version, const hidl_string& service_name,
    flushServices_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::flushServicesInternal, _hidl_cb, version, service_name);
}

Return<void> P2pIface::requestServiceDiscovery(
    const hidl_array<uint8_t, 6>& peer_address, const hidl_vec<uint8_t>& query,
    requestServiceDiscovery_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::requestServiceDiscoveryInternal, _hidl_cb, version,
	    peer_address, query);
}

Return<void> P2pIface::cancelServiceDiscovery(
    uint64_t identifier, cancelServiceDiscovery_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &P2pIface::cancelServiceDiscoveryInternal, _hidl_cb, identifier);
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
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
	struct wpa_ssid* ssid = wpa_supplicant_add_network(wpa_s);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getP2pNetworkHidlObjectByIfnameAndNetworkId(
		wpa_s->ifname, ssid->id, &network)) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, network};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, network};
}

SupplicantStatus P2pIface::removeNetworkInternal(SupplicantNetworkId id)
{
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
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
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
	struct wpa_ssid* ssid = wpa_config_get_network(wpa_s->conf, id);
	if (!ssid) {
		return {{SupplicantStatusCode::FAILURE_NETWORK_UNKNOWN, ""},
			network};
	}
	HidlManager* hidl_manager = HidlManager::getInstance();
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
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
	for (struct wpa_ssid* wpa_ssid = wpa_s->conf->ssid; wpa_ssid;
	     wpa_ssid = wpa_ssid->next) {
		network_ids.emplace_back(wpa_ssid->id);
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, std::move(network_ids)};
}

SupplicantStatus P2pIface::registerCallbackInternal(
    const sp<ISupplicantP2pIfaceCallback>& callback)
{
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addP2pIfaceCallbackHidlObject(ifname_, callback)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, std::array<uint8_t, 6>>
P2pIface::getDeviceAddressInternal()
{
	// TODO: Add implementation.
	return {{SupplicantStatusCode::SUCCESS, ""}, {}};
}

SupplicantStatus P2pIface::setSsidPostfixInternal(const hidl_string& postfix)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::setGroupIdleInternal(uint32_t timeout_in_sec)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::setPowerSaveInternal(bool enable)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::findInternal(uint32_t timeout_in_sec)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::stopFindInternal()
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::flushInternal()
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, std::vector<uint8_t>> P2pIface::connectInternal(
    const hidl_array<uint8_t, 6>& peer_address,
    ISupplicantP2pIface::WpsProvisionMethod provision_method,
    const hidl_vec<uint8_t>& pre_selected_pin, bool join_existing_group,
    bool persistent, uint32_t go_intent)
{
	// TODO: Add implementation.
	return {{SupplicantStatusCode::SUCCESS, ""}, {}};
}

SupplicantStatus P2pIface::cancelConnectInternal()
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::provisionDiscoveryInternal(
    const hidl_array<uint8_t, 6>& peer_address,
    ISupplicantP2pIface::WpsProvisionMethod provision_method)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::addGroupInternal(
    bool persistent, uint32_t persistent_network_id)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::removeGroupInternal(const hidl_string& group_ifname)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::rejectInternal(
    const hidl_array<uint8_t, 6>& peer_address)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::inviteInternal(
    const hidl_string& group_ifname,
    const hidl_array<uint8_t, 6>& go_device_address,
    const hidl_array<uint8_t, 6>& peer_address)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::reinvokeInternal(
    uint32_t persistent_network_id, const hidl_array<uint8_t, 6>& peer_address)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::configureExtListenInternal(
    bool enable, uint32_t period_in_millis, uint32_t interval_in_millis)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::setListenChannelInternal(
    uint32_t channel, uint32_t operating_class)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, std::vector<uint8_t>> P2pIface::getSsidInternal(
    const hidl_array<uint8_t, 6>& peer_address)
{
	// TODO: Add implementation.
	return {{SupplicantStatusCode::SUCCESS, ""}, {}};
}

std::pair<SupplicantStatus, uint32_t> P2pIface::getGroupCapabilityInternal(
    const hidl_array<uint8_t, 6>& peer_address)
{
	// TODO: Add implementation.
	return {{SupplicantStatusCode::SUCCESS, ""}, 0};
}

SupplicantStatus P2pIface::addBonjourServiceInternal(
    const hidl_vec<uint8_t>& query, const hidl_vec<uint8_t>& response)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::removeBonjourServiceInternal(
    const hidl_vec<uint8_t>& query)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::addUpnpServiceInternal(
    uint32_t version, const hidl_string& service_name)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::removeUpnpServiceInternal(
    uint32_t version, const hidl_string& service_name)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus P2pIface::flushServicesInternal(
    uint32_t version, const hidl_string& service_name)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, uint64_t> P2pIface::requestServiceDiscoveryInternal(
    const hidl_array<uint8_t, 6>& peer_address, const hidl_vec<uint8_t>& query)
{
	// TODO: Add implementation.
	return {{SupplicantStatusCode::SUCCESS, ""}, 0};
}

SupplicantStatus P2pIface::cancelServiceDiscoveryInternal(uint64_t identifier)
{
	// TODO: Add implementation.
	return {SupplicantStatusCode::SUCCESS, ""};
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this iface.
 * If the underlying iface is removed, then all RPC method calls on this object
 * will return failure.
 */
wpa_supplicant* P2pIface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(
	    (struct wpa_global*)wpa_global_, ifname_.c_str());
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

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
#include "supplicant.h"

namespace {
// Pre-populated interface params for interfaces controlled by wpa_supplicant.
// Note: This may differ for other OEM's. So, modify this accordingly.
constexpr char kIfaceDriverName[] = "nl80211";
constexpr char kStaIfaceConfPath[] =
		"/data/misc/wifi/wpa_supplicant.conf";
constexpr char kStaIfaceConfOverlayPath[] =
		"/vendor/etc/wifi/wpa_supplicant_overlay.conf";
constexpr char kP2pIfaceConfPath[] =
		"/data/misc/wifi/p2p_supplicant.conf";
constexpr char kP2pIfaceConfOverlayPath[] =
		"/vendor/etc/wifi/p2p_supplicant_overlay.conf";
}  // namespace

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_1 {
namespace implementation {
using hidl_return_util::validateAndCall;

Supplicant::Supplicant(struct wpa_global* global) : wpa_global_(global) {}
bool Supplicant::isValid()
{
	// This top level object cannot be invalidated.
	return true;
}

Return<void> Supplicant::addInterface(
    const IfaceInfo& iface_info, addInterface_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::addInterfaceInternal, _hidl_cb, iface_info);
}

Return<void> Supplicant::removeInterface(
    const IfaceInfo& iface_info, removeInterface_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::removeInterfaceInternal, _hidl_cb, iface_info);
}

Return<void> Supplicant::getInterface(
    const IfaceInfo& iface_info, getInterface_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::getInterfaceInternal, _hidl_cb, iface_info);
}

Return<void> Supplicant::listInterfaces(listInterfaces_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::listInterfacesInternal, _hidl_cb);
}

Return<void> Supplicant::registerCallback(
    const sp<ISupplicantCallback>& callback, registerCallback_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::registerCallbackInternal, _hidl_cb, callback);
}

Return<void> Supplicant::setDebugParams(
    ISupplicant::DebugLevel level, bool show_timestamp, bool show_keys,
    setDebugParams_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::setDebugParamsInternal, _hidl_cb, level,
	    show_timestamp, show_keys);
}

Return<void> Supplicant::setConcurrencyPriority(
    IfaceType type, setConcurrencyPriority_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &Supplicant::setConcurrencyPriorityInternal, _hidl_cb, type);
}

Return<ISupplicant::DebugLevel> Supplicant::getDebugLevel()
{
	// TODO: Add SupplicantStatus in this method return for uniformity with
	// the other methods in supplicant HIDL interface.
	return (ISupplicant::DebugLevel)wpa_debug_level;
}

Return<bool> Supplicant::isDebugShowTimestampEnabled()
{
	// TODO: Add SupplicantStatus in this method return for uniformity with
	// the other methods in supplicant HIDL interface.
	return ((wpa_debug_timestamp != 0) ? true : false);
}

Return<bool> Supplicant::isDebugShowKeysEnabled()
{
	// TODO: Add SupplicantStatus in this method return for uniformity with
	// the other methods in supplicant HIDL interface.
	return ((wpa_debug_show_keys != 0) ? true : false);
}

std::pair<SupplicantStatus, sp<ISupplicantIface>>
Supplicant::addInterfaceInternal(const IfaceInfo& iface_info)
{
	android::sp<ISupplicantIface> iface;

	// Check if required |ifname| argument is empty.
	if (iface_info.name.empty()) {
		return {{SupplicantStatusCode::FAILURE_ARGS_INVALID, ""}, {}};
	}
	// Try to get the wpa_supplicant record for this iface, return
	// the iface object with the appropriate status code if it exists.
	SupplicantStatus status;
	std::tie(status, iface) = getInterfaceInternal(iface_info);
	if (status.code == SupplicantStatusCode::SUCCESS) {
		return {{SupplicantStatusCode::FAILURE_IFACE_EXISTS, ""},
			iface};
	}

	struct wpa_interface iface_params = {};
	iface_params.driver = kIfaceDriverName;
	if (iface_info.type == IfaceType::P2P) {
		iface_params.confname = kP2pIfaceConfPath;
		iface_params.confanother = kP2pIfaceConfOverlayPath;
	} else {
		iface_params.confname = kStaIfaceConfPath;
		iface_params.confanother = kStaIfaceConfOverlayPath;
	}
	iface_params.ifname = iface_info.name.c_str();
	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_add_iface(wpa_global_, &iface_params, NULL);
	if (!wpa_s) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
	}
	// The supplicant core creates a corresponding hidl object via
	// HidlManager when |wpa_supplicant_add_iface| is called.
	return getInterfaceInternal(iface_info);
}

SupplicantStatus Supplicant::removeInterfaceInternal(
    const IfaceInfo& iface_info)
{
	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_get_iface(wpa_global_, iface_info.name.c_str());
	if (!wpa_s) {
		return {SupplicantStatusCode::FAILURE_IFACE_UNKNOWN, ""};
	}
	if (wpa_supplicant_remove_iface(wpa_global_, wpa_s, 0)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, sp<ISupplicantIface>>
Supplicant::getInterfaceInternal(const IfaceInfo& iface_info)
{
	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_get_iface(wpa_global_, iface_info.name.c_str());
	if (!wpa_s) {
		return {{SupplicantStatusCode::FAILURE_IFACE_UNKNOWN, ""},
			nullptr};
	}
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (iface_info.type == IfaceType::P2P) {
		android::sp<ISupplicantP2pIface> iface;
		if (!hidl_manager ||
		    hidl_manager->getP2pIfaceHidlObjectByIfname(
			wpa_s->ifname, &iface)) {
			return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""},
				iface};
		}
		// Set this flag true here, since there is no HIDL initialize method for the p2p
		// config, and the supplicant interface is not ready when the p2p iface is created.
		wpa_s->conf->persistent_reconnect = true;
		return {{SupplicantStatusCode::SUCCESS, ""}, iface};
	} else {
		android::sp<ISupplicantStaIface> iface;
		if (!hidl_manager ||
		    hidl_manager->getStaIfaceHidlObjectByIfname(
			wpa_s->ifname, &iface)) {
			return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""},
				iface};
		}
		return {{SupplicantStatusCode::SUCCESS, ""}, iface};
	}
}

std::pair<SupplicantStatus, std::vector<ISupplicant::IfaceInfo>>
Supplicant::listInterfacesInternal()
{
	std::vector<ISupplicant::IfaceInfo> ifaces;
	for (struct wpa_supplicant* wpa_s = wpa_global_->ifaces; wpa_s;
	     wpa_s = wpa_s->next) {
		if (wpa_s->global->p2p_init_wpa_s == wpa_s) {
			ifaces.emplace_back(ISupplicant::IfaceInfo{
			    IfaceType::P2P, wpa_s->ifname});
		} else {
			ifaces.emplace_back(ISupplicant::IfaceInfo{
			    IfaceType::STA, wpa_s->ifname});
		}
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, std::move(ifaces)};
}

SupplicantStatus Supplicant::registerCallbackInternal(
    const sp<ISupplicantCallback>& callback)
{
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addSupplicantCallbackHidlObject(callback)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus Supplicant::setDebugParamsInternal(
    ISupplicant::DebugLevel level, bool show_timestamp, bool show_keys)
{
	if (wpa_supplicant_set_debug_params(
		wpa_global_, static_cast<uint32_t>(level), show_timestamp,
		show_keys)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus Supplicant::setConcurrencyPriorityInternal(IfaceType type)
{
	if (type == IfaceType::STA) {
		wpa_global_->conc_pref =
		    wpa_global::wpa_conc_pref::WPA_CONC_PREF_STA;
	} else if (type == IfaceType::P2P) {
		wpa_global_->conc_pref =
		    wpa_global::wpa_conc_pref::WPA_CONC_PREF_P2P;
	} else {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	return SupplicantStatus{SupplicantStatusCode::SUCCESS, ""};
}
}  // namespace implementation
}  // namespace V1_1
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

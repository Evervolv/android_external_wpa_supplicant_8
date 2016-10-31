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
#include "supplicant.h"

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

// These are hardcoded for android.
const char Supplicant::kDriverName[] = "nl80211";
const char Supplicant::kConfigFilePath[] =
    "/data/misc/wifi/wpa_supplicant.conf";

Supplicant::Supplicant(struct wpa_global* global) : wpa_global_(global) {}
Return<void> Supplicant::createInterface(
    const hidl_string& ifname, createInterface_cb _hidl_cb)
{
	android::sp<ISupplicantIface> iface;

	// Check if required |ifname| argument is empty.
	if (ifname.size() == 0) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_ARGS_INVALID, iface);
	}
	// Try to get the wpa_supplicant record for this iface, return
	// an error if we already control it.
	if (wpa_supplicant_get_iface(wpa_global_, ifname.c_str()) != NULL) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_EXISTS, iface);
	}

	// Otherwise, have wpa_supplicant attach to it.
	struct wpa_supplicant* wpa_s = NULL;
	struct wpa_interface iface_params;
	os_memset(&iface_params, 0, sizeof(iface));
	iface_params.ifname = ifname.c_str();
	iface_params.confname = kConfigFilePath;
	iface_params.driver = kDriverName;
	wpa_s = wpa_supplicant_add_iface(wpa_global_, &iface_params, NULL);
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, iface);
	}
	// The supplicant core creates a corresponding hidl object via
	// HidlManager when |wpa_supplicant_add_iface| is called.
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getIfaceHidlObjectByIfname(wpa_s->ifname, &iface)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, iface);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, iface);
}

Return<void> Supplicant::removeInterface(
    const hidl_string& ifname, removeInterface_cb _hidl_cb)
{
	struct wpa_supplicant* wpa_s;

	wpa_s = wpa_supplicant_get_iface(wpa_global_, ifname.c_str());
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN);
	}
	if (wpa_supplicant_remove_iface(wpa_global_, wpa_s, 0)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Supplicant::getInterface(
    const hidl_string& ifname, getInterface_cb _hidl_cb)
{
	android::sp<ISupplicantIface> iface;

	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_get_iface(wpa_global_, ifname.c_str());
	if (!wpa_s) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN, iface);
	}

	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->getIfaceHidlObjectByIfname(wpa_s->ifname, &iface)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN, iface);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, iface);
}

Return<void> Supplicant::listInterfaces(listInterfaces_cb _hidl_cb)
{
	std::vector<hidl_string> ifnames;
	for (struct wpa_supplicant* wpa_s = wpa_global_->ifaces; wpa_s;
	     wpa_s = wpa_s->next) {
		ifnames.emplace_back(wpa_s->ifname);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, ifnames);
}

Return<void> Supplicant::registerCallback(
    const sp<ISupplicantCallback>& callback, registerCallback_cb _hidl_cb)
{
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addSupplicantCallbackHidlObject(callback)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<void> Supplicant::setDebugParams(
    ISupplicant::DebugLevel level, bool show_timestamp, bool show_keys,
    setDebugParams_cb _hidl_cb)
{
	if (wpa_supplicant_set_debug_params(
		wpa_global_, static_cast<uint32_t>(level), show_timestamp,
		show_keys)) {
		HIDL_RETURN(SupplicantStatusCode::FAILURE_UNKNOWN);
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS);
}

Return<ISupplicant::DebugLevel> Supplicant::getDebugLevel()
{
	return (ISupplicant::DebugLevel)wpa_debug_level;
}

Return<bool> Supplicant::isDebugShowTimestampEnabled()
{
	return (wpa_debug_timestamp ? true : false);
}

Return<bool> Supplicant::isDebugShowKeysEnabled()
{
	return (wpa_debug_show_keys ? true : false);
}
}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

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
Return<void> Supplicant::getInterface(
    const IfaceInfo& iface_info, getInterface_cb _hidl_cb)
{
	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_get_iface(wpa_global_, iface_info.name.c_str());
	if (!wpa_s) {
		HIDL_RETURN(
		    SupplicantStatusCode::FAILURE_IFACE_UNKNOWN, nullptr);
	}

	HidlManager* hidl_manager = HidlManager::getInstance();
	if (iface_info.type == IfaceType::P2P) {
		android::sp<ISupplicantP2pIface> iface;
		if (!hidl_manager ||
		    hidl_manager->getP2pIfaceHidlObjectByIfname(
			wpa_s->ifname, &iface)) {
			HIDL_RETURN(
			    SupplicantStatusCode::FAILURE_UNKNOWN, iface);
		}

		HIDL_RETURN(SupplicantStatusCode::SUCCESS, iface);
	} else {
		android::sp<ISupplicantStaIface> iface;
		if (!hidl_manager ||
		    hidl_manager->getStaIfaceHidlObjectByIfname(
			wpa_s->ifname, &iface)) {
			HIDL_RETURN(
			    SupplicantStatusCode::FAILURE_UNKNOWN, iface);
		}

		HIDL_RETURN(SupplicantStatusCode::SUCCESS, iface);
	}
}

Return<void> Supplicant::listInterfaces(listInterfaces_cb _hidl_cb)
{
	std::vector<ISupplicant::IfaceInfo> ifaces;
	for (struct wpa_supplicant* wpa_s = wpa_global_->ifaces; wpa_s;
	     wpa_s = wpa_s->next) {
		if (wpa_s->global->p2p_init_wpa_s == wpa_s) {
			ifaces.emplace_back({IfaceType::P2P, wpa_s->ifname});
		} else {
			ifaces.emplace_back({IfaceType::STA, wpa_s->ifname});
		}
	}

	HIDL_RETURN(SupplicantStatusCode::SUCCESS, ifaces);
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

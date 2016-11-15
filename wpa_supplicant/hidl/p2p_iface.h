/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_P2P_IFACE_H
#define WPA_SUPPLICANT_HIDL_P2P_IFACE_H

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pIface.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pNetwork.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "driver_i.h"
}

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

/**
 * Implementation of P2pIface hidl object. Each unique hidl
 * object is used for control operations on a specific interface
 * controlled by wpa_supplicant.
 */
class P2pIface
    : public android::hardware::wifi::supplicant::V1_0::ISupplicantP2pIface
{
public:
	P2pIface(struct wpa_global* wpa_global, const char ifname[]);
	~P2pIface() override = default;
	// Refer to |StaIface::invalidate()|.
	void invalidate();
	bool isValid();

	// Hidl methods exposed.
	Return<void> getName(getName_cb _hidl_cb) override;
	Return<void> getType(getType_cb _hidl_cb) override;
	Return<void> addNetwork(addNetwork_cb _hidl_cb) override;
	Return<void> removeNetwork(
	    SupplicantNetworkId id, removeNetwork_cb _hidl_cb) override;
	Return<void> getNetwork(
	    SupplicantNetworkId id, getNetwork_cb _hidl_cb) override;
	Return<void> listNetworks(listNetworks_cb _hidl_cb) override;
	Return<void> registerCallback(
	    const sp<ISupplicantP2pIfaceCallback>& callback,
	    registerCallback_cb _hidl_cb) override;

private:
	// Corresponding worker functions for the HIDL methods.
	std::pair<SupplicantStatus, std::string> getNameInternal();
	std::pair<SupplicantStatus, IfaceType> getTypeInternal();
	std::pair<SupplicantStatus, sp<ISupplicantP2pNetwork>>
	addNetworkInternal();
	SupplicantStatus removeNetworkInternal(SupplicantNetworkId id);
	std::pair<SupplicantStatus, sp<ISupplicantP2pNetwork>>
	getNetworkInternal(SupplicantNetworkId id);
	std::pair<SupplicantStatus, std::vector<SupplicantNetworkId>>
	listNetworksInternal();
	SupplicantStatus registerCallbackInternal(
	    const sp<ISupplicantP2pIfaceCallback>& callback);

	struct wpa_supplicant* retrieveIfacePtr();

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global* wpa_global_;
	// Name of the iface this hidl object controls
	const std::string ifname_;
	bool is_valid_;

	DISALLOW_COPY_AND_ASSIGN(P2pIface);
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

#endif  // WPA_SUPPLICANT_HIDL_P2P_IFACE_H

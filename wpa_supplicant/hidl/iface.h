/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_IFACE_H
#define WPA_SUPPLICANT_HIDL_IFACE_H

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.0/ISupplicantIface.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantNetwork.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
}

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

/**
 * Implementation of Iface hidl object. Each unique hidl
 * object is used for control operations on a specific interface
 * controlled by wpa_supplicant.
 */
class Iface : public android::hardware::wifi::supplicant::V1_0::ISupplicantIface
{
public:
	Iface(struct wpa_global* wpa_global, const char ifname[]);
	~Iface() override = default;

	// Hidl methods exposed.
	Return<void> getName(getName_cb _hidl_cb) override;
	Return<void> addNetwork(addNetwork_cb _hidl_cb) override;
	Return<void> removeNetwork(
	    uint32_t id, removeNetwork_cb _hidl_cb) override;
	Return<void> getNetwork(uint32_t id, getNetwork_cb _hidl_cb) override;
	Return<void> listNetworks(listNetworks_cb _hidl_cb) override;
	Return<void> registerCallback(
	    const sp<ISupplicantIfaceCallback>& callback,
	    registerCallback_cb _hidl_cb) override;
	Return<void> reassociate(reassociate_cb _hidl_cb) override;
	Return<void> reconnect(reconnect_cb _hidl_cb) override;
	Return<void> disconnect(disconnect_cb _hidl_cb) override;
	Return<void> setPowerSave(
	    bool enable, setPowerSave_cb _hidl_cb) override;
	Return<void> initiateTdlsDiscover(
	    const hidl_array<uint8_t, 6 /* 6 */>& mac_address,
	    initiateTdlsDiscover_cb _hidl_cb) override;
	Return<void> initiateTdlsSetup(
	    const hidl_array<uint8_t, 6 /* 6 */>& mac_address,
	    initiateTdlsSetup_cb _hidl_cb) override;
	Return<void> initiateTdlsTeardown(
	    const hidl_array<uint8_t, 6 /* 6 */>& mac_address,
	    initiateTdlsTeardown_cb _hidl_cb) override;

private:
	struct wpa_supplicant* retrieveIfacePtr();

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global* wpa_global_;
	// Name of the iface this hidl object controls
	const std::string ifname_;

	DISALLOW_COPY_AND_ASSIGN(Iface);
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

#endif  // WPA_SUPPLICANT_HIDL_IFACE_H

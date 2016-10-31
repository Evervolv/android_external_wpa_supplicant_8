/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_SUPPLICANT_H
#define WPA_SUPPLICANT_HIDL_SUPPLICANT_H

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.0/ISupplicant.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantIface.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "utils/wpa_debug.h"
#include "wpa_supplicant_i.h"
}

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {
/**
 * Implementation of the supplicant hidl object. This hidl
 * object is used core for global control operations on
 * wpa_supplicant.
 */
class Supplicant : public android::hardware::wifi::supplicant::V1_0::ISupplicant
{
public:
	Supplicant(struct wpa_global* global);
	~Supplicant() override = default;

	// Hidl methods exposed.
	Return<void> createInterface(
	    const hidl_string& ifname, createInterface_cb _hidl_cb) override;
	Return<void> removeInterface(
	    const hidl_string& ifname, removeInterface_cb _hidl_cb) override;
	Return<void> getInterface(
	    const hidl_string& ifname, getInterface_cb _hidl_cb) override;
	Return<void> listInterfaces(listInterfaces_cb _hidl_cb) override;
	Return<void> registerCallback(
	    const sp<ISupplicantCallback>& callback,
	    registerCallback_cb _hidl_cb) override;
	Return<void> setDebugParams(
	    ISupplicant::DebugLevel level, bool show_timestamp, bool show_keys,
	    setDebugParams_cb _hidl_cb) override;
	Return<ISupplicant::DebugLevel> getDebugLevel() override;
	Return<bool> isDebugShowTimestampEnabled() override;
	Return<bool> isDebugShowKeysEnabled() override;

private:
	// Raw pointer to the global structure maintained by the core.
	struct wpa_global* wpa_global_;
	// Driver name to be used for creating interfaces.
	static const char kDriverName[];
	// wpa_supplicant.conf file location on the device.
	static const char kConfigFilePath[];

	DISALLOW_COPY_AND_ASSIGN(Supplicant);
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android

#endif  // WPA_SUPPLICANT_HIDL_SUPPLICANT_H

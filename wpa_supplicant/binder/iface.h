/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_BINDER_IFACE_H
#define WPA_SUPPLICANT_BINDER_IFACE_H

#include <android-base/macros.h>

#include "fi/w1/wpa_supplicant/BnIface.h"
#include "fi/w1/wpa_supplicant/INetwork.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
}

namespace wpa_supplicant_binder {

/**
 * Implementation of Iface binder object. Each unique binder
 * object is used for control operations on a specific interface
 * controlled by wpa_supplicant.
 */
class Iface : public fi::w1::wpa_supplicant::BnIface
{
public:
	Iface(struct wpa_global *wpa_global, const char ifname[]);
	~Iface() override = default;

	// Binder methods exposed in aidl.
	android::binder::Status GetName(std::string *iface_name_out) override;
	android::binder::Status AddNetwork(
	    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object_out)
	    override;
	android::binder::Status RemoveNetwork(int network_id) override;
	android::binder::Status GetNetwork(
	    int network_id,
	    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object_out)
	    override;
	android::binder::Status RegisterCallback(
	    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback> &callback)
	    override;
	android::binder::Status Reassociate() override;
	android::binder::Status Reconnect() override;
	android::binder::Status Disconnect() override;
	android::binder::Status SetPowerSave(bool enable) override;
	android::binder::Status InitiateTDLSDiscover(
	    const std::vector<uint8_t> &mac_address) override;
	android::binder::Status InitiateTDLSSetup(
	    const std::vector<uint8_t> &mac_address) override;
	android::binder::Status InitiateTDLSTeardown(
	    const std::vector<uint8_t> &mac_address) override;

private:
	struct wpa_supplicant *retrieveIfacePtr();

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global *wpa_global_;
	// Name of the iface this binder object controls
	const std::string ifname_;

	DISALLOW_COPY_AND_ASSIGN(Iface);
};

}  // namespace wpa_supplicant_binder

#endif  // WPA_SUPPLICANT_BINDER_IFACE_H

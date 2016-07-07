/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_BINDER_NETWORK_H
#define WPA_SUPPLICANT_BINDER_NETWORK_H

#include <android-base/macros.h>

#include "fi/w1/wpa_supplicant/BnNetwork.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "../config.h"
#include "../wpa_supplicant_i.h"
}

namespace wpa_supplicant_binder {

/**
 * Implementation of Network binder object. Each unique binder
 * object is used for control operations on a specific network
 * controlled by wpa_supplicant.
 */
class Network : public fi::w1::wpa_supplicant::BnNetwork
{
public:
	Network(
	    struct wpa_global *wpa_global, const char ifname[], int network_id);
	~Network() override = default;

	// Binder methods exposed in aidl.
	android::binder::Status GetId(int *network_id_out) override;
	android::binder::Status
	GetInterfaceName(std::string *ifname_out) override;

private:
	struct wpa_ssid *retrieveNetworkPtr();

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global *wpa_global_;
	// Name of the iface this network belongs to.
	const std::string ifname_;
	// Id of the network this binder object controls.
	const int network_id_;

	DISALLOW_COPY_AND_ASSIGN(Network);
};

} // namespace wpa_supplicant_binder

#endif // WPA_SUPPLICANT_BINDER_NETWORK_H

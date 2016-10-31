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

#include "fi/w1/wpa_supplicant/BnIface.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "../wpa_supplicant_i.h"
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
	virtual ~Iface() = default;

	// Binder methods exposed in aidl.
	android::binder::Status GetName(std::string *iface_name_out) override;

private:
	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global *wpa_global_;
	// Name of the iface this binder object controls
	const std::string ifname_;

	struct wpa_supplicant *retrieveIfacePtr();
};

} // namespace wpa_supplicant_binder

#endif // WPA_SUPPLICANT_BINDER_IFACE_H

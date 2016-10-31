/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "iface.h"

namespace wpa_supplicant_binder {

Iface::Iface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname)
{
}

android::binder::Status Iface::GetName(std::string *iface_name_out)
{
	// We could directly return the name we hold, but let's verify
	// if the underlying iface still exists.
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_IFACE_UNKNOWN,
		    "wpa_supplicant does not control this interface.");
	}

	*iface_name_out = ifname_;
	return android::binder::Status::ok();
}

/**
 * Retrieve the underlying |wpa_supplicant| struct pointer for
 * this iface.
 * If the underlying iface is removed, then all RPC method calls
 * on this object will return failure.
 */
wpa_supplicant *Iface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
}

} // namespace wpa_supplicant_binder

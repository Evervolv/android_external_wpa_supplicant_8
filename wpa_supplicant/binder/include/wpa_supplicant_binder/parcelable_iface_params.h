/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_BINDER_PARCELABLE_IFACE_PARAMS_H
#define WPA_SUPPLICANT_BINDER_PARCELABLE_IFACE_PARAMS_H

#include <binder/Parcelable.h>
#include <utils/String8.h>

namespace fi {
namespace w1 {
namespace wpa_supplicant {

// Parcelable object containing the params used for creating a
// new interface via |ISupplicant.CreateInterface| binder call.
class ParcelableIfaceParams : public android::Parcelable
{
public:
	ParcelableIfaceParams() = default;
	virtual ~ParcelableIfaceParams() = default;

	android::status_t writeToParcel(android::Parcel *parcel) const override;
	android::status_t readFromParcel(const android::Parcel *parcel) override;

	// Name of the network interface to control, e.g., wlan0.
	android::String8 ifname_;
	// BridgeIfname(String) Name of the bridge interface to control, e.g.,
	// br0.
	android::String8 bridge_ifname_;
	// Driver name which the interface uses, e.g., nl80211.
	android::String8 driver_;
	// Configuration file path.
	android::String8 config_file_;
};

} // namespace fi
} // namespace w1
} // namespace wpa_supplicant

#endif // WPA_SUPPLICANT_BINDER_PARCELABLE_IFACE_PARAMS_H

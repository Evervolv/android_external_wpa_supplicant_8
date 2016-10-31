/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <binder/Parcel.h>

#include "wpa_supplicant_binder/parcelable_iface_params.h"

namespace fi {
namespace w1 {
namespace wpa_supplicant {

android::status_t ParcelableIfaceParams::writeToParcel(
    android::Parcel *parcel) const
{
	android::status_t status;
	status = parcel->writeString8(ifname_);
	if (status != android::OK) {
		return status;
	}
	status = parcel->writeString8(bridge_ifname_);
	if (status != android::OK) {
		return status;
	}
	status = parcel->writeString8(driver_);
	if (status != android::OK) {
		return status;
	}
	return parcel->writeString8(config_file_);
}

android::status_t ParcelableIfaceParams::readFromParcel(
    const android::Parcel *parcel)
{
	android::status_t status;
	status = parcel->readString8(&ifname_);
	if (status != android::OK) {
		return status;
	}
	status = parcel->readString8(&bridge_ifname_);
	if (status != android::OK) {
		return status;
	}
	status = parcel->readString8(&driver_);
	if (status != android::OK) {
		return status;
	}
	return parcel->readString8(&config_file_);
}

}  // namespace fi
}  // namespace w1
}  // namespace wpa_supplicant

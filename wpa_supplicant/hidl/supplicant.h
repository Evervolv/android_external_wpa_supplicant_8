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

#include "fi/w1/wpa_supplicant/BnSupplicant.h"
#include "fi/w1/wpa_supplicant/IIface.h"
#include "fi/w1/wpa_supplicant/ISupplicantCallback.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "../wpa_supplicant_i.h"
}

namespace wpa_supplicant_hidl {

/**
 * Implementation of the supplicant hidl object. This hidl
 * object is used core for global control operations on
 * wpa_supplicant.
 */
class Supplicant : public fi::w1::wpa_supplicant::BnSupplicant
{
public:
	Supplicant(struct wpa_global *global);
	~Supplicant() override = default;

	// Hidl methods exposed in aidl.
	android::hidl::Status CreateInterface(
	    const fi::w1::wpa_supplicant::ParcelableIfaceParams &params,
	    android::sp<fi::w1::wpa_supplicant::IIface> *iface_object_out)
	    override;
	android::hidl::Status RemoveInterface(
	    const std::string &ifname) override;
	android::hidl::Status GetInterface(
	    const std::string &ifname,
	    android::sp<fi::w1::wpa_supplicant::IIface> *iface_object_out)
	    override;
	android::hidl::Status SetDebugParams(
	    int level, bool show_timestamp, bool show_keys) override;
	android::hidl::Status GetDebugLevel(int *level_out) override;
	android::hidl::Status GetDebugShowTimestamp(
	    bool *show_timestamp_out) override;
	android::hidl::Status GetDebugShowKeys(bool *show_keys_out) override;
	android::hidl::Status RegisterCallback(
	    const android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>
		&callback) override;

private:
	int convertDebugLevelToInternalLevel(
	    int external_level, int *internal_level);
	int convertDebugLevelToExternalLevel(
	    int internal_level, int *external_level);

	/* Raw pointer to the global structure maintained by the core. */
	struct wpa_global *wpa_global_;
	/* All the callback objects registered by the clients. */
	std::vector<android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>>
	    callbacks_;

	DISALLOW_COPY_AND_ASSIGN(Supplicant);
};

} /* namespace wpa_supplicant_hidl */

#endif /* WPA_SUPPLICANT_HIDL_SUPPLICANT_H */

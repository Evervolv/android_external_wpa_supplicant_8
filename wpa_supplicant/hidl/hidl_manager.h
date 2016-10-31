/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_HIDL_MANAGER_H
#define WPA_SUPPLICANT_HIDL_HIDL_MANAGER_H

#include <map>
#include <string>

#include <android/hardware/wifi/supplicant/1.0/ISupplicantCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantNetworkCallback.h>

#include "iface.h"
#include "network.h"
#include "supplicant.h"

struct wpa_global;
struct wpa_supplicant;

namespace android {
namespace hardware {
namespace wifi {
namespace supplicant {
namespace V1_0 {
namespace implementation {

/**
 * HidlManager is responsible for managing the lifetime of all
 * hidl objects created by wpa_supplicant. This is a singleton
 * class which is created by the supplicant core and can be used
 * to get references to the hidl objects.
 */
class HidlManager
{
public:
	static HidlManager *getInstance();
	static void destroyInstance();

	// Methods called from wpa_supplicant core.
	int registerHidlService(struct wpa_global *global);
	int registerInterface(struct wpa_supplicant *wpa_s);
	int unregisterInterface(struct wpa_supplicant *wpa_s);
	int registerNetwork(
	    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
	int unregisterNetwork(
	    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
	int notifyStateChange(struct wpa_supplicant *wpa_s);
	int notifyNetworkRequest(
	    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid, int type,
	    const char *param);

	// Methods called from hidl objects.
	int getIfaceHidlObjectByIfname(
	    const std::string &ifname,
	    android::sp<
		android::hardware::wifi::supplicant::V1_0::ISupplicantIface>
		*iface_object);
	int getNetworkHidlObjectByIfnameAndNetworkId(
	    const std::string &ifname, int network_id,
	    android::sp<
		android::hardware::wifi::supplicant::V1_0::ISupplicantNetwork>
		*network_object);
	int addSupplicantCallbackHidlObject(
	    const android::sp<
		android::hardware::wifi::supplicant::V1_0::ISupplicantCallback>
		&callback);
	int addIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<android::hardware::wifi::supplicant::V1_0::
				  ISupplicantIfaceCallback> &callback);
	int addNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<android::hardware::wifi::supplicant::V1_0::
				  ISupplicantNetworkCallback> &callback);

private:
	HidlManager() = default;
	~HidlManager() = default;
	HidlManager(const HidlManager &) = default;
	HidlManager &operator=(const HidlManager &) = default;

	const std::string getNetworkObjectMapKey(
	    const std::string &ifname, int network_id);

	void removeSupplicantCallbackHidlObject(
	    const android::sp<
		android::hardware::wifi::supplicant::V1_0::ISupplicantCallback>
		&callback);
	void removeIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<android::hardware::wifi::supplicant::V1_0::
				  ISupplicantIfaceCallback> &callback);
	void removeNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<android::hardware::wifi::supplicant::V1_0::
				  ISupplicantNetworkCallback> &callback);
	template <class CallbackType>
	int registerForDeathAndAddCallbackHidlObjectToList(
	    const android::sp<CallbackType> &callback,
	    const std::function<void(const android::sp<CallbackType> &)>
		&on_hidl_died_fctor,
	    std::vector<android::sp<CallbackType>> &callback_list);

	void callWithEachSupplicantCallback(
	    const std::function<android::hardware::Return<void>(
		android::sp<android::hardware::wifi::supplicant::V1_0::
				ISupplicantCallback>)> &method);
	void callWithEachIfaceCallback(
	    const std::string &ifname,
	    const std::function<android::hardware::Return<void>(
		android::sp<android::hardware::wifi::supplicant::V1_0::
				ISupplicantIfaceCallback>)> &method);
	void callWithEachNetworkCallback(
	    const std::string &ifname, int network_id,
	    const std::function<android::hardware::Return<void>(
		android::sp<android::hardware::wifi::supplicant::V1_0::
				ISupplicantNetworkCallback>)> &method);

	// HIDL Service name.
	static const char kServiceName[];
	// Singleton instance of this class.
	static HidlManager *instance_;
	// The main hidl service object.
	android::sp<Supplicant> supplicant_object_;
	// Map of all the interface specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname|.
	std::map<const std::string, android::sp<Iface>> iface_object_map_;
	// Map of all the network specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname| & |network_id|.
	std::map<const std::string, android::sp<Network>> network_object_map_;

	// Callback registered for the main hidl service object.
	std::vector<android::sp<
	    android::hardware::wifi::supplicant::V1_0::ISupplicantCallback>>
	    supplicant_callbacks_;
	// Map of all the callbacks registered for interface specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname|.
	std::map<
	    const std::string,
	    std::vector<android::sp<android::hardware::wifi::supplicant::V1_0::
					ISupplicantIfaceCallback>>>
	    iface_callbacks_map_;
	// Map of all the callbacks registered for network specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname| & |network_id|.
	std::map<
	    const std::string,
	    std::vector<android::sp<android::hardware::wifi::supplicant::V1_0::
					ISupplicantNetworkCallback>>>
	    network_callbacks_map_;

	/**
	 * Helper class used to deregister the callback object reference from
	 * our callback list on the death of the hidl object.
	 * This class stores a reference of the callback hidl object and a
	 * function to be called to indicate the death of the hidl object.
	 */
	template <class CallbackType>
	class CallbackObjectDeathNotifier
	    : public android::hardware::IBinder::DeathRecipient
	{
	public:
		CallbackObjectDeathNotifier(
		    const android::sp<CallbackType> &callback,
		    const std::function<void(const android::sp<CallbackType> &)>
			&on_hidl_died)
		    : callback_(callback), on_hidl_died_(on_hidl_died)
		{
		}
		void binderDied(const android::wp<android::hardware::IBinder>
				    & /* who */) override
		{
			on_hidl_died_(callback_);
		}

	private:
		// The callback hidl object reference.
		const android::sp<CallbackType> callback_;
		// Callback function to be called when the hidl dies.
		const std::function<void(const android::sp<CallbackType> &)>
		    on_hidl_died_;
	};
};

// The hidl interface uses some values which are the same as internal ones to
// avoid nasty runtime conversion functions. So, adding compile time asserts
// to guard against any internal changes breaking the hidl interface.
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicant::DebugLevel::EXCESSIVE) ==
	MSG_EXCESSIVE,
    "Debug level value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicant::DebugLevel::ERROR) == MSG_ERROR,
    "Debug level value mismatch");

static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::KeyMgmtMask::NONE) ==
	WPA_KEY_MGMT_NONE,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::KeyMgmtMask::WPA_PSK) ==
	WPA_KEY_MGMT_PSK,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::KeyMgmtMask::WPA_EAP) ==
	WPA_KEY_MGMT_IEEE8021X,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::KeyMgmtMask::IEEE8021X) ==
	WPA_KEY_MGMT_IEEE8021X_NO_WPA,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::ProtoMask::WPA) ==
	WPA_PROTO_WPA,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::ProtoMask::RSN) ==
	WPA_PROTO_RSN,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::ProtoMask::OSEN) ==
	WPA_PROTO_OSEN,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::AuthAlgMask::OPEN) ==
	WPA_AUTH_ALG_OPEN,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::AuthAlgMask::SHARED) ==
	WPA_AUTH_ALG_SHARED,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::AuthAlgMask::LEAP) ==
	WPA_AUTH_ALG_LEAP,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::GroupCipherMask::WEP40) ==
	WPA_CIPHER_WEP40,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::GroupCipherMask::WEP104) ==
	WPA_CIPHER_WEP104,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::GroupCipherMask::TKIP) ==
	WPA_CIPHER_TKIP,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::GroupCipherMask::CCMP) ==
	WPA_CIPHER_CCMP,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::PairwiseCipherMask::NONE) ==
	WPA_CIPHER_NONE,
    "PairwiseCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::PairwiseCipherMask::TKIP) ==
	WPA_CIPHER_TKIP,
    "PairwiseCipher value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantNetwork::PairwiseCipherMask::CCMP) ==
	WPA_CIPHER_CCMP,
    "PairwiseCipher value mismatch");

static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantIfaceCallback::State::DISCONNECTED) ==
	WPA_DISCONNECTED,
    "State value mismatch");
static_assert(
    static_cast<uint32_t>(android::hardware::wifi::supplicant::V1_0::
			      ISupplicantIfaceCallback::State::COMPLETED) ==
	WPA_COMPLETED,
    "State value mismatch");

}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android
#endif  // WPA_SUPPLICANT_HIDL_HIDL_MANAGER_H

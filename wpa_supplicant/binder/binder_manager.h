/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_BINDER_BINDER_MANAGER_H
#define WPA_SUPPLICANT_BINDER_BINDER_MANAGER_H

#include <map>
#include <string>

#include "fi/w1/wpa_supplicant/IIfaceCallback.h"
#include "fi/w1/wpa_supplicant/INetworkCallback.h"
#include "fi/w1/wpa_supplicant/ISupplicantCallback.h"

#include "iface.h"
#include "network.h"
#include "supplicant.h"

struct wpa_global;
struct wpa_supplicant;

namespace wpa_supplicant_binder {

/**
 * BinderManager is responsible for managing the lifetime of all
 * binder objects created by wpa_supplicant. This is a singleton
 * class which is created by the supplicant core and can be used
 * to get references to the binder objects.
 */
class BinderManager
{
public:
	static BinderManager *getInstance();
	static void destroyInstance();

	// Methods called from wpa_supplicant core.
	int registerBinderService(struct wpa_global *global);
	int registerInterface(struct wpa_supplicant *wpa_s);
	int unregisterInterface(struct wpa_supplicant *wpa_s);
	int
	registerNetwork(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
	int
	unregisterNetwork(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
	int notifyStateChange(struct wpa_supplicant *wpa_s);

	// Methods called from binder objects.
	int getIfaceBinderObjectByIfname(
	    const std::string &ifname,
	    android::sp<fi::w1::wpa_supplicant::IIface> *iface_object);
	int getNetworkBinderObjectByIfnameAndNetworkId(
	    const std::string &ifname, int network_id,
	    android::sp<fi::w1::wpa_supplicant::INetwork> *network_object);
	int addSupplicantCallbackBinderObject(
	    const android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>
		&callback);
	int addIfaceCallbackBinderObject(
	    const std::string &ifname,
	    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback>
		&callback);
	int addNetworkCallbackBinderObject(
	    const std::string &ifname, int network_id,
	    const android::sp<fi::w1::wpa_supplicant::INetworkCallback>
		&callback);

private:
	BinderManager() = default;
	~BinderManager() = default;
	BinderManager(const BinderManager &) = default;
	BinderManager &operator=(const BinderManager &) = default;

	const std::string
	getNetworkObjectMapKey(const std::string &ifname, int network_id);

	void removeSupplicantCallbackBinderObject(
	    const android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>
		&callback);
	void removeIfaceCallbackBinderObject(
	    const std::string &ifname,
	    const android::sp<fi::w1::wpa_supplicant::IIfaceCallback>
		&callback);
	void removeNetworkCallbackBinderObject(
	    const std::string &ifname, int network_id,
	    const android::sp<fi::w1::wpa_supplicant::INetworkCallback>
		&callback);
	template <class CallbackType>
	int registerForDeathAndAddCallbackBinderObjectToList(
	    const android::sp<CallbackType> &callback,
	    const std::function<void(const android::sp<CallbackType> &)>
		&on_binder_died_fctor,
	    std::vector<android::sp<CallbackType>> &callback_list);

	void callWithEachSupplicantCallback(
	    const std::function<android::binder::Status(
		android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>)>
		&method);
	void callWithEachIfaceCallback(
	    const std::string &ifname,
	    const std::function<android::binder::Status(
		android::sp<fi::w1::wpa_supplicant::IIfaceCallback>)> &method);
	void callWithEachNetworkCallback(
	    const std::string &ifname, int network_id,
	    const std::function<android::binder::Status(
		android::sp<fi::w1::wpa_supplicant::INetworkCallback>)>
		&method);

	// Singleton instance of this class.
	static BinderManager *instance_;
	// The main binder service object.
	android::sp<Supplicant> supplicant_object_;
	// Map of all the interface specific binder objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname|.
	std::map<const std::string, android::sp<Iface>> iface_object_map_;
	// Map of all the network specific binder objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname| & |network_id|.
	std::map<const std::string, android::sp<Network>> network_object_map_;

	// Callback registered for the main binder service object.
	std::vector<android::sp<fi::w1::wpa_supplicant::ISupplicantCallback>>
	    supplicant_callbacks_;
	// Map of all the callbacks registered for interface specific
	// binder objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname|.
	std::map<
	    const std::string,
	    std::vector<android::sp<fi::w1::wpa_supplicant::IIfaceCallback>>>
	    iface_callbacks_map_;
	// Map of all the callbacks registered for network specific
	// binder objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname| & |network_id|.
	std::map<
	    const std::string,
	    std::vector<android::sp<fi::w1::wpa_supplicant::INetworkCallback>>>
	    network_callbacks_map_;

	/**
	 * Helper class used to deregister the callback object reference from
	 * our
	 * callback list on the death of the binder object.
	 * This class stores a reference of the callback binder object and a
	 * function to be called to indicate the death of the binder object.
	 */
	template <class CallbackType>
	class CallbackObjectDeathNotifier
	    : public android::IBinder::DeathRecipient
	{
	public:
		CallbackObjectDeathNotifier(
		    const android::sp<CallbackType> &callback,
		    const std::function<void(const android::sp<CallbackType> &)>
			&on_binder_died)
		    : callback_(callback), on_binder_died_(on_binder_died)
		{
		}
		void binderDied(
		    const android::wp<android::IBinder> & /* who */) override
		{
			on_binder_died_(callback_);
		}

	private:
		// The callback binder object reference.
		const android::sp<CallbackType> callback_;
		// Callback function to be called when the binder dies.
		const std::function<void(const android::sp<CallbackType> &)>
		    on_binder_died_;
	};
};

// The binder interface uses some values which are the same as internal ones to
// avoid nasty runtime conversion functions.  So, adding compile time asserts
// to guard against any internal changes breaking the binder interface.
static_assert(
    fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_NONE == WPA_KEY_MGMT_NONE,
    "KeyMgmt value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_WPA_PSK == WPA_KEY_MGMT_PSK,
    "KeyMgmt value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_WPA_EAP ==
	WPA_KEY_MGMT_IEEE8021X,
    "KeyMgmt value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_IEEE8021X ==
	WPA_KEY_MGMT_IEEE8021X_NO_WPA,
    "KeyMgmt value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PROTO_MASK_WPA == WPA_PROTO_WPA,
    "Proto value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PROTO_MASK_RSN == WPA_PROTO_RSN,
    "Proto value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PROTO_MASK_OSEN == WPA_PROTO_OSEN,
    "Proto value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_OPEN == WPA_AUTH_ALG_OPEN,
    "AuthAlg value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_SHARED ==
	WPA_AUTH_ALG_SHARED,
    "AuthAlg value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_LEAP == WPA_AUTH_ALG_LEAP,
    "AuthAlg value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_WEP40 ==
	WPA_CIPHER_WEP40,
    "GroupCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_WEP104 ==
	WPA_CIPHER_WEP104,
    "GroupCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_TKIP == WPA_CIPHER_TKIP,
    "GroupCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_CCMP == WPA_CIPHER_CCMP,
    "GroupCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_NONE ==
	WPA_CIPHER_NONE,
    "PairwiseCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_TKIP ==
	WPA_CIPHER_TKIP,
    "PairwiseCipher value mismatch");
static_assert(
    fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_CCMP ==
	WPA_CIPHER_CCMP,
    "PairwiseCipher value mismatch");

static_assert(
    WPA_DISCONNECTED ==
	fi::w1::wpa_supplicant::IIfaceCallback::STATE_DISCONNECTED,
    "State value mismatch");
static_assert(
    WPA_COMPLETED == fi::w1::wpa_supplicant::IIfaceCallback::STATE_COMPLETED,
    "State value mismatch");
} // namespace wpa_supplicant_binder
#endif // WPA_SUPPLICANT_BINDER_BINDER_MANAGER_H

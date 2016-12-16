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
#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pNetworkCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaNetworkCallback.h>

#include "p2p_iface.h"
#include "p2p_network.h"
#include "sta_iface.h"
#include "sta_network.h"
#include "supplicant.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
}

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
	void notifyAnqpQueryDone(
	    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *result,
	    const struct wpa_bss_anqp *anqp);
	void notifyHs20IconQueryDone(
	    struct wpa_supplicant *wpa_s, const u8 *bssid,
	    const char *file_name, const u8 *image, u32 image_length);
	void notifyHs20RxSubscriptionRemediation(
	    struct wpa_supplicant *wpa_s, const char *url, u8 osu_method);
	void notifyHs20RxDeauthImminentNotice(
	    struct wpa_supplicant *wpa_s, u8 code, u16 reauth_delay,
	    const char *url);
	void notifyDisconnectReason(struct wpa_supplicant *wpa_s);
	void notifyAssocReject(struct wpa_supplicant *wpa_s);

	// Methods called from hidl objects.
	int getP2pIfaceHidlObjectByIfname(
	    const std::string &ifname,
	    android::sp<ISupplicantP2pIface> *iface_object);
	int getStaIfaceHidlObjectByIfname(
	    const std::string &ifname,
	    android::sp<ISupplicantStaIface> *iface_object);
	int getP2pNetworkHidlObjectByIfnameAndNetworkId(
	    const std::string &ifname, int network_id,
	    android::sp<ISupplicantP2pNetwork> *network_object);
	int getStaNetworkHidlObjectByIfnameAndNetworkId(
	    const std::string &ifname, int network_id,
	    android::sp<ISupplicantStaNetwork> *network_object);
	int addSupplicantCallbackHidlObject(
	    const android::sp<ISupplicantCallback> &callback);
	int addP2pIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<ISupplicantP2pIfaceCallback> &callback);
	int addStaIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<ISupplicantStaIfaceCallback> &callback);
	int addP2pNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<ISupplicantP2pNetworkCallback> &callback);
	int addStaNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<ISupplicantStaNetworkCallback> &callback);

private:
	HidlManager() = default;
	~HidlManager() = default;
	HidlManager(const HidlManager &) = default;
	HidlManager &operator=(const HidlManager &) = default;

	void removeSupplicantCallbackHidlObject(
	    const android::sp<ISupplicantCallback> &callback);
	void removeP2pIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<ISupplicantP2pIfaceCallback> &callback);
	void removeStaIfaceCallbackHidlObject(
	    const std::string &ifname,
	    const android::sp<ISupplicantStaIfaceCallback> &callback);
	void removeP2pNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<ISupplicantP2pNetworkCallback> &callback);
	void removeStaNetworkCallbackHidlObject(
	    const std::string &ifname, int network_id,
	    const android::sp<ISupplicantStaNetworkCallback> &callback);

	void callWithEachSupplicantCallback(
	    const std::function<android::hardware::Return<void>(
		android::sp<ISupplicantCallback>)> &method);
	void callWithEachP2pIfaceCallback(
	    const std::string &ifname,
	    const std::function<android::hardware::Return<void>(
		android::sp<ISupplicantP2pIfaceCallback>)> &method);
	void callWithEachStaIfaceCallback(
	    const std::string &ifname,
	    const std::function<android::hardware::Return<void>(
		android::sp<ISupplicantStaIfaceCallback>)> &method);
	void callWithEachP2pNetworkCallback(
	    const std::string &ifname, int network_id,
	    const std::function<android::hardware::Return<void>(
		android::sp<ISupplicantP2pNetworkCallback>)> &method);
	void callWithEachStaNetworkCallback(
	    const std::string &ifname, int network_id,
	    const std::function<android::hardware::Return<void>(
		android::sp<ISupplicantStaNetworkCallback>)> &method);

	// HIDL Service name.
	static const char kServiceName[];
	// Singleton instance of this class.
	static HidlManager *instance_;
	// The main hidl service object.
	android::sp<Supplicant> supplicant_object_;
	// Map of all the P2P interface specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname|.
	std::map<const std::string, android::sp<P2pIface>>
	    p2p_iface_object_map_;
	// Map of all the STA interface specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname|.
	std::map<const std::string, android::sp<StaIface>>
	    sta_iface_object_map_;
	// Map of all the P2P network specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname| & |network_id|.
	std::map<const std::string, android::sp<P2pNetwork>>
	    p2p_network_object_map_;
	// Map of all the STA network specific hidl objects controlled by
	// wpa_supplicant. This map is keyed in by the corresponding
	// |ifname| & |network_id|.
	std::map<const std::string, android::sp<StaNetwork>>
	    sta_network_object_map_;

	// Callback registered for the main hidl service object.
	std::vector<android::sp<ISupplicantCallback>> supplicant_callbacks_;
	// Map of all the callbacks registered for P2P interface specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname|.
	std::map<
	    const std::string,
	    std::vector<android::sp<ISupplicantP2pIfaceCallback>>>
	    p2p_iface_callbacks_map_;
	// Map of all the callbacks registered for STA interface specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname|.
	std::map<
	    const std::string,
	    std::vector<android::sp<ISupplicantStaIfaceCallback>>>
	    sta_iface_callbacks_map_;
	// Map of all the callbacks registered for P2P network specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname| & |network_id|.
	std::map<
	    const std::string,
	    std::vector<android::sp<ISupplicantP2pNetworkCallback>>>
	    p2p_network_callbacks_map_;
	// Map of all the callbacks registered for STA network specific
	// hidl objects controlled by wpa_supplicant.  This map is keyed in by
	// the corresponding |ifname| & |network_id|.
	std::map<
	    const std::string,
	    std::vector<android::sp<ISupplicantStaNetworkCallback>>>
	    sta_network_callbacks_map_;

#if 0  // TODO(b/31632518): HIDL object death notifications.
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
#endif
};

// The hidl interface uses some values which are the same as internal ones to
// avoid nasty runtime conversion functions. So, adding compile time asserts
// to guard against any internal changes breaking the hidl interface.
static_assert(
    static_cast<uint32_t>(ISupplicant::DebugLevel::EXCESSIVE) == MSG_EXCESSIVE,
    "Debug level value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicant::DebugLevel::ERROR) == MSG_ERROR,
    "Debug level value mismatch");

static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::KeyMgmtMask::NONE) ==
	WPA_KEY_MGMT_NONE,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::KeyMgmtMask::WPA_PSK) ==
	WPA_KEY_MGMT_PSK,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::KeyMgmtMask::WPA_EAP) ==
	WPA_KEY_MGMT_IEEE8021X,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::KeyMgmtMask::IEEE8021X) ==
	WPA_KEY_MGMT_IEEE8021X_NO_WPA,
    "KeyMgmt value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::ProtoMask::WPA) ==
	WPA_PROTO_WPA,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::ProtoMask::RSN) ==
	WPA_PROTO_RSN,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::ProtoMask::OSEN) ==
	WPA_PROTO_OSEN,
    "Proto value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::AuthAlgMask::OPEN) ==
	WPA_AUTH_ALG_OPEN,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::AuthAlgMask::SHARED) ==
	WPA_AUTH_ALG_SHARED,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::AuthAlgMask::LEAP) ==
	WPA_AUTH_ALG_LEAP,
    "AuthAlg value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::GroupCipherMask::WEP40) ==
	WPA_CIPHER_WEP40,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::GroupCipherMask::WEP104) ==
	WPA_CIPHER_WEP104,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::GroupCipherMask::TKIP) ==
	WPA_CIPHER_TKIP,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::GroupCipherMask::CCMP) ==
	WPA_CIPHER_CCMP,
    "GroupCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::PairwiseCipherMask::NONE) ==
	WPA_CIPHER_NONE,
    "PairwiseCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::PairwiseCipherMask::TKIP) ==
	WPA_CIPHER_TKIP,
    "PairwiseCipher value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaNetwork::PairwiseCipherMask::CCMP) ==
	WPA_CIPHER_CCMP,
    "PairwiseCipher value mismatch");

static_assert(
    static_cast<uint32_t>(ISupplicantStaIfaceCallback::State::DISCONNECTED) ==
	WPA_DISCONNECTED,
    "State value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaIfaceCallback::State::COMPLETED) ==
	WPA_COMPLETED,
    "State value mismatch");

static_assert(
    static_cast<uint32_t>(ISupplicantStaIface::AnqpInfoId::VENUE_NAME) ==
	ANQP_VENUE_NAME,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::AnqpInfoId::ROAMING_CONSORTIUM) ==
	ANQP_ROAMING_CONSORTIUM,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaIface::AnqpInfoId::NAI_REALM) ==
	ANQP_NAI_REALM,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::AnqpInfoId::IP_ADDR_TYPE_AVAILABILITY) ==
	ANQP_IP_ADDR_TYPE_AVAILABILITY,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::AnqpInfoId::ANQP_3GPP_CELLULAR_NETWORK) ==
	ANQP_3GPP_CELLULAR_NETWORK,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaIface::AnqpInfoId::DOMAIN_NAME) ==
	ANQP_DOMAIN_NAME,
    "ANQP ID value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::Hs20AnqpSubtypes::OPERATOR_FRIENDLY_NAME) ==
	HS20_STYPE_OPERATOR_FRIENDLY_NAME,
    "HS Subtype value mismatch");
static_assert(
    static_cast<uint32_t>(ISupplicantStaIface::Hs20AnqpSubtypes::WAN_METRICS) ==
	HS20_STYPE_WAN_METRICS,
    "HS Subtype value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::Hs20AnqpSubtypes::CONNECTION_CAPABILITY) ==
	HS20_STYPE_CONNECTION_CAPABILITY,
    "HS Subtype value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantStaIface::Hs20AnqpSubtypes::OSU_PROVIDERS_LIST) ==
	HS20_STYPE_OSU_PROVIDERS_LIST,
    "HS Subtype value mismatch");

static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::GROUP_OWNER) ==
	P2P_GROUP_CAPAB_GROUP_OWNER,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::PERSISTENT_GROUP) ==
	P2P_GROUP_CAPAB_PERSISTENT_GROUP,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::GROUP_LIMIT) ==
	P2P_GROUP_CAPAB_GROUP_LIMIT,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::INTRA_BSS_DIST) ==
	P2P_GROUP_CAPAB_INTRA_BSS_DIST,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::CROSS_CONN) ==
	P2P_GROUP_CAPAB_CROSS_CONN,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::PERSISTENT_RECONN) ==
	P2P_GROUP_CAPAB_PERSISTENT_RECONN,
    "P2P capability value mismatch");
static_assert(
    static_cast<uint32_t>(
	ISupplicantP2pIface::GroupCapabilityMask::GROUP_FORMATION) ==
	P2P_GROUP_CAPAB_GROUP_FORMATION,
    "P2P capability value mismatch");
}  // namespace implementation
}  // namespace V1_0
}  // namespace wifi
}  // namespace supplicant
}  // namespace hardware
}  // namespace android
#endif  // WPA_SUPPLICANT_HIDL_HIDL_MANAGER_H

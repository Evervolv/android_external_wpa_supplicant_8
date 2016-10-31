/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "binder_manager.h"
#include "network.h"

namespace wpa_supplicant_binder {

#define RETURN_IF_NETWORK_INVALID(wpa_ssid)                                    \
	{                                                                      \
		if (!wpa_ssid) {                                               \
			return android::binder::Status::                       \
			    fromServiceSpecificError(                          \
				ERROR_NETWORK_INVALID, "wpa_supplicant does "  \
						       "not control this "     \
						       "network.");            \
		}                                                              \
	} // #define RETURN_IF_NETWORK_INVALID(wpa_ssid)

Network::Network(
    struct wpa_global *wpa_global, const char ifname[], int network_id)
    : wpa_global_(wpa_global), ifname_(ifname), network_id_(network_id)
{
}

android::binder::Status Network::GetId(int *network_id_out)
{
	RETURN_IF_NETWORK_INVALID(retrieveNetworkPtr());
	*network_id_out = network_id_;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetInterfaceName(std::string *ifname_out)
{
	RETURN_IF_NETWORK_INVALID(retrieveNetworkPtr());
	*ifname_out = ifname_;
	return android::binder::Status::ok();
}

android::binder::Status Network::RegisterCallback(
    const android::sp<fi::w1::wpa_supplicant::INetworkCallback> &callback)
{
	RETURN_IF_NETWORK_INVALID(retrieveNetworkPtr());
	BinderManager *binder_manager = BinderManager::getInstance();
	if (!binder_manager ||
	    binder_manager->addNetworkCallbackBinderObject(
		ifname_, network_id_, callback)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "wpa_supplicant encountered a binder error.");
	}
	return android::binder::Status::ok();
}

android::binder::Status Network::SetSSID(const std::vector<uint8_t> &ssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetBSSID(const std::vector<uint8_t> &bssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetScanSSID(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetKeyMgmt(int32_t key_mgmt_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetProto(int32_t proto_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetAuthAlg(int32_t auth_alg_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetGroupCipher(int32_t group_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetPairwiseCipher(int32_t pairwise_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetPskPassphrase(const std::string &psk)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status
Network::SetWepKey(int key_idx, const std::vector<uint8_t> &wep_key)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetWepTxKeyIdx(int32_t wep_tx_key_idx)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetRequirePMF(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetSSID(std::vector<uint8_t> *ssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetBSSID(std::vector<uint8_t> *bssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetScanSSID(bool *enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetKeyMgmt(int32_t *key_mgmt_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetProto(int32_t *proto_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetAuthAlg(int32_t *auth_alg_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetGroupCipher(int32_t *group_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status
Network::GetPairwiseCipher(int32_t *pairwise_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetPskPassphrase(std::string *psk)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status
Network::GetWepKey(int key_idx, std::vector<uint8_t> *wep_key)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetWepTxKeyIdx(int32_t *wep_tx_key_idx)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetRequirePMF(bool *enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::Enable(bool no_connect)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::Disable()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::Select()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	return android::binder::Status::ok();
}

/**
 * Retrieve the underlying |wpa_ssid| struct pointer for
 * this network.
 * If the underlying network is removed or the interface this network belong to
 * is removed, all RPC method calls on this object will return failure.
 */
struct wpa_ssid *Network::retrieveNetworkPtr()
{
	wpa_supplicant *wpa_s = wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
	if (!wpa_s)
		return nullptr;
	return wpa_config_get_network(wpa_s->conf, network_id_);
}

} // namespace wpa_supplicant_binder

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

namespace {
constexpr int kAllowedKeyMgmtMask =
    (fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_NONE |
     fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_WPA_PSK |
     fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_WPA_EAP |
     fi::w1::wpa_supplicant::INetwork::KEY_MGMT_MASK_IEEE8021X);
constexpr int kAllowedProtoMask =
    (fi::w1::wpa_supplicant::INetwork::PROTO_MASK_WPA |
     fi::w1::wpa_supplicant::INetwork::PROTO_MASK_RSN |
     fi::w1::wpa_supplicant::INetwork::PROTO_MASK_OSEN);
constexpr int kAllowedAuthAlgMask =
    (fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_OPEN |
     fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_SHARED |
     fi::w1::wpa_supplicant::INetwork::AUTH_ALG_MASK_LEAP);
constexpr int kAllowedGroupCipherMask =
    (fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_WEP40 |
     fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_WEP104 |
     fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_TKIP |
     fi::w1::wpa_supplicant::INetwork::GROUP_CIPHER_MASK_CCMP);
constexpr int kAllowedPairwiseCipherMask =
    (fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_NONE |
     fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_TKIP |
     fi::w1::wpa_supplicant::INetwork::PAIRWISE_CIPHER_MASK_CCMP);
} // namespace

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

	if (ssid.empty() || ssid.size() > SSID_MAX_LEN) {
		const std::string error_msg = "Invalid SSID value length: " +
					      std::to_string(ssid.size()) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	// Free any existing ssid string.
	if (wpa_ssid->ssid) {
		os_free(wpa_ssid);
	}
	// This array needs to be a null terminated!.
	wpa_ssid->ssid = (uint8_t *)os_malloc(ssid.size() + 1);
	if (!wpa_ssid->ssid) {
		return android::binder::Status::fromExceptionCode(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	os_memcpy(wpa_ssid->ssid, ssid.data(), ssid.size());
	wpa_ssid->ssid[ssid.size()] = '\0';
	wpa_ssid->ssid_len = ssid.size();
	if (wpa_ssid->passphrase) {
		wpa_config_update_psk(wpa_ssid);
	}
	wpa_hexdump_ascii(
	    MSG_MSGDUMP, "SSID", wpa_ssid->ssid, wpa_ssid->ssid_len);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetBSSID(const std::vector<uint8_t> &bssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (!bssid.empty() && bssid.size() != BSSID_LEN) {
		const std::string error_msg = "Invalid BSSID value length: " +
					      std::to_string(bssid.size()) +
					      ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	// Empty array is used to clear out the BSSID value.
	if (bssid.empty()) {
		wpa_ssid->bssid_set = 0;
		wpa_printf(MSG_MSGDUMP, "BSSID any");
	} else {
		os_memcpy(wpa_ssid->bssid, bssid.data(), ETH_ALEN);
		wpa_ssid->bssid_set = 1;
		wpa_hexdump(MSG_MSGDUMP, "BSSID", wpa_ssid->bssid, ETH_ALEN);
	}
	return android::binder::Status::ok();
}

android::binder::Status Network::SetScanSSID(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	wpa_ssid->scan_ssid = enable ? 1 : 0;
	return android::binder::Status::ok();
}

android::binder::Status Network::SetKeyMgmt(int32_t key_mgmt_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (key_mgmt_mask & ~kAllowedKeyMgmtMask) {
		const std::string error_msg = "Invalid key_mgmt value: " +
					      std::to_string(key_mgmt_mask) +
					      ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->key_mgmt = key_mgmt_mask;
	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", wpa_ssid->key_mgmt);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetProto(int32_t proto_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (proto_mask & ~kAllowedProtoMask) {
		const std::string error_msg =
		    "Invalid proto value: " + std::to_string(proto_mask) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->proto = proto_mask;
	wpa_printf(MSG_MSGDUMP, "proto: 0x%x", wpa_ssid->proto);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetAuthAlg(int32_t auth_alg_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (auth_alg_mask & ~kAllowedAuthAlgMask) {
		const std::string error_msg = "Invalid auth_alg value: " +
					      std::to_string(auth_alg_mask) +
					      ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->auth_alg = auth_alg_mask;
	wpa_printf(MSG_MSGDUMP, "auth_alg: 0x%x", wpa_ssid->auth_alg);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetGroupCipher(int32_t group_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (group_cipher_mask & ~kAllowedGroupCipherMask) {
		const std::string error_msg =
		    "Invalid group_cipher value: " +
		    std::to_string(group_cipher_mask) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->group_cipher = group_cipher_mask;
	wpa_printf(MSG_MSGDUMP, "group_cipher: 0x%x", wpa_ssid->group_cipher);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetPairwiseCipher(int32_t pairwise_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (pairwise_cipher_mask & ~kAllowedPairwiseCipherMask) {
		const std::string error_msg =
		    "Invalid pairwise_cipher value: " +
		    std::to_string(pairwise_cipher_mask) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->pairwise_cipher = pairwise_cipher_mask;
	wpa_printf(
	    MSG_MSGDUMP, "pairwise_cipher: 0x%x", wpa_ssid->pairwise_cipher);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetPskPassphrase(const std::string &psk)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (isPskPassphraseValid(psk)) {
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    "Invalid Psk passphrase value.");
	}
	if (wpa_ssid->passphrase &&
	    os_strlen(wpa_ssid->passphrase) == psk.size() &&
	    os_memcmp(wpa_ssid->passphrase, psk.c_str(), psk.size()) == 0) {
		return android::binder::Status::ok();
	}
	// Flag to indicate if raw psk is calculated or not using
	// |wpa_config_update_psk|. Deferred if ssid not already set.
	wpa_ssid->psk_set = 0;
	str_clear_free(wpa_ssid->passphrase);
	wpa_ssid->passphrase = dup_binstr(psk.c_str(), psk.size());
	if (!wpa_ssid->passphrase) {
		return android::binder::Status::fromExceptionCode(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	if (wpa_ssid->ssid_len) {
		wpa_config_update_psk(wpa_ssid);
	}
	wpa_hexdump_ascii_key(
	    MSG_MSGDUMP, "PSK (ASCII passphrase)", (u8 *)wpa_ssid->passphrase,
	    psk.size());
	return android::binder::Status::ok();
}

android::binder::Status
Network::SetWepKey(int key_idx, const std::vector<uint8_t> &wep_key)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (key_idx < 0 || key_idx >= WEP_KEYS_MAX_NUM) {
		const std::string error_msg =
		    "Invalid Wep Key index: " + std::to_string(key_idx) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	if (wep_key.size() != WEP40_KEY_LEN &&
	    wep_key.size() != WEP104_KEY_LEN) {
		const std::string error_msg = "Invalid Wep Key value length: " +
					      std::to_string(wep_key.size()) +
					      ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	os_memcpy(wpa_ssid->wep_key[key_idx], wep_key.data(), wep_key.size());
	wpa_ssid->wep_key_len[key_idx] = wep_key.size();
	std::string msg_dump_title("wep_key" + std::to_string(key_idx));
	wpa_hexdump_key(
	    MSG_MSGDUMP, msg_dump_title.c_str(), wpa_ssid->wep_key[key_idx],
	    wpa_ssid->wep_key_len[key_idx]);
	return android::binder::Status::ok();
}

android::binder::Status Network::SetWepTxKeyIdx(int32_t wep_tx_key_idx)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wep_tx_key_idx < 0 || wep_tx_key_idx >= WEP_KEYS_MAX_NUM) {
		const std::string error_msg = "Invalid Wep Key index: " +
					      std::to_string(wep_tx_key_idx) +
					      ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	wpa_ssid->wep_tx_keyidx = wep_tx_key_idx;
	return android::binder::Status::ok();
}

android::binder::Status Network::SetRequirePMF(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	wpa_ssid->ieee80211w =
	    enable ? MGMT_FRAME_PROTECTION_REQUIRED : NO_MGMT_FRAME_PROTECTION;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetSSID(std::vector<uint8_t> *ssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	ssid->assign(wpa_ssid->ssid, wpa_ssid->ssid + wpa_ssid->ssid_len);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetBSSID(std::vector<uint8_t> *bssid)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wpa_ssid->bssid_set) {
		bssid->assign(wpa_ssid->bssid, wpa_ssid->bssid + ETH_ALEN);
	} else {
		bssid->clear();
	}
	return android::binder::Status::ok();
}

android::binder::Status Network::GetScanSSID(bool *enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	*enable = (wpa_ssid->scan_ssid == 1);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetKeyMgmt(int32_t *key_mgmt_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*key_mgmt_mask = wpa_ssid->key_mgmt;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetProto(int32_t *proto_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*proto_mask = wpa_ssid->proto;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetAuthAlg(int32_t *auth_alg_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*auth_alg_mask = wpa_ssid->auth_alg;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetGroupCipher(int32_t *group_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*group_cipher_mask = wpa_ssid->group_cipher;
	return android::binder::Status::ok();
}

android::binder::Status
Network::GetPairwiseCipher(int32_t *pairwise_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*pairwise_cipher_mask = wpa_ssid->pairwise_cipher;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetPskPassphrase(std::string *psk)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wpa_ssid->passphrase) {
		*psk = wpa_ssid->passphrase;
	} else {
		*psk = std::string();
	}
	return android::binder::Status::ok();
}

android::binder::Status
Network::GetWepKey(int key_idx, std::vector<uint8_t> *wep_key)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (key_idx < 0 || key_idx >= WEP_KEYS_MAX_NUM) {
		const std::string error_msg =
		    "Invalid Wep Key index: " + std::to_string(key_idx) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}

	wep_key->assign(
	    wpa_ssid->wep_key[key_idx],
	    wpa_ssid->wep_key[key_idx] + wpa_ssid->wep_key_len[key_idx]);
	return android::binder::Status::ok();
}

android::binder::Status Network::GetWepTxKeyIdx(int32_t *wep_tx_key_idx)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	*wep_tx_key_idx = wpa_ssid->wep_tx_keyidx;
	return android::binder::Status::ok();
}

android::binder::Status Network::GetRequirePMF(bool *enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	*enable = (wpa_ssid->ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED);
	return android::binder::Status::ok();
}

android::binder::Status Network::Enable(bool no_connect)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wpa_ssid->disabled == 2) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "Cannot use Enable with persistent P2P group");
	}

	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (no_connect) {
		wpa_ssid->disabled = 0;
	} else {
		wpa_s->scan_min_time.sec = 0;
		wpa_s->scan_min_time.usec = 0;
		wpa_supplicant_enable_network(wpa_s, wpa_ssid);
	}
	return android::binder::Status::ok();
}

android::binder::Status Network::Disable()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wpa_ssid->disabled == 2) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "Cannot use Disable with persistent P2P group");
	}

	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	wpa_supplicant_disable_network(wpa_s, wpa_ssid);
	return android::binder::Status::ok();
}

android::binder::Status Network::Select()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (wpa_ssid->disabled == 2) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC,
		    "Cannot use Select with persistent P2P group");
	}

	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	wpa_s->scan_min_time.sec = 0;
	wpa_s->scan_min_time.usec = 0;
	wpa_supplicant_select_network(wpa_s, wpa_ssid);
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
	wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s)
		return nullptr;
	return wpa_config_get_network(wpa_s->conf, network_id_);
}

/**
 * Retrieve the underlying |wpa_supplicant| struct pointer for
 * this network.
 */
struct wpa_supplicant *Network::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(
	    (struct wpa_global *)wpa_global_, ifname_.c_str());
}

/**
 * Check if the provided psk passhrase is valid or not.
 *
 * Returns 0 if valid, 1 otherwise.
 */
int Network::isPskPassphraseValid(const std::string &psk)
{
	if (psk.size() < PSK_PASSPHRASE_MIN_LEN ||
	    psk.size() > PSK_PASSPHRASE_MAX_LEN) {
		return 1;
	}
	if (has_ctrl_char((u8 *)psk.c_str(), psk.size())) {
		return 1;
	}
	return 0;
}
} // namespace wpa_supplicant_binder

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

constexpr int kEapMethodMax =
    fi::w1::wpa_supplicant::INetwork::EAP_METHOD_WFA_UNAUTH_TLS + 1;
constexpr int kEapMethodMin = fi::w1::wpa_supplicant::INetwork::EAP_METHOD_PEAP;
constexpr char const *kEapMethodStrings[kEapMethodMax] = {
    "PEAP", "TLS", "TTLS", "PWD", "SIM", "AKA", "AKA'", "WFA-UNAUTH-TLS"};

constexpr int kEapPhase2MethodMax =
    fi::w1::wpa_supplicant::INetwork::EAP_PHASE2_METHOD_GTC + 1;
constexpr int kEapPhase2MethodMin =
    fi::w1::wpa_supplicant::INetwork::EAP_PHASE2_METHOD_NONE;
constexpr char const *kEapPhase2MethodStrings[kEapPhase2MethodMax] = {
    "NULL", "PAP", "MSCHAP", "MSCHAPV2", "GTC"};
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

	android::binder::Status status = setByteArrayKeyFieldAndResetState(
	    ssid.data(), ssid.size(), &(wpa_ssid->ssid), &(wpa_ssid->ssid_len),
	    "ssid");
	if (status.isOk() && wpa_ssid->passphrase) {
		wpa_config_update_psk(wpa_ssid);
	}
	return status;
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
	int prev_bssid_set = wpa_ssid->bssid_set;
	u8 prev_bssid[ETH_ALEN];
	os_memcpy(prev_bssid, wpa_ssid->bssid, ETH_ALEN);
	// Empty array is used to clear out the BSSID value.
	if (bssid.empty()) {
		wpa_ssid->bssid_set = 0;
		wpa_printf(MSG_MSGDUMP, "BSSID any");
	} else {
		os_memcpy(wpa_ssid->bssid, bssid.data(), ETH_ALEN);
		wpa_ssid->bssid_set = 1;
		wpa_hexdump(MSG_MSGDUMP, "BSSID", wpa_ssid->bssid, ETH_ALEN);
	}
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if ((wpa_ssid->bssid_set != prev_bssid_set ||
	     os_memcmp(wpa_ssid->bssid, prev_bssid, ETH_ALEN) != 0)) {
		wpas_notify_network_bssid_set_changed(wpa_s, wpa_ssid);
	}
	return android::binder::Status::ok();
}

android::binder::Status Network::SetScanSSID(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	wpa_ssid->scan_ssid = enable ? 1 : 0;
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
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
	android::binder::Status status = setStringKeyFieldAndResetState(
	    psk.data(), &(wpa_ssid->passphrase), "psk passphrase");
	if (status.isOk() && wpa_ssid->ssid_len) {
		wpa_config_update_psk(wpa_ssid);
	}
	return status;
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
	resetInternalStateAfterParamsUpdate();
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
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

android::binder::Status Network::SetRequirePMF(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	wpa_ssid->ieee80211w =
	    enable ? MGMT_FRAME_PROTECTION_REQUIRED : NO_MGMT_FRAME_PROTECTION;
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

android::binder::Status Network::SetEapMethod(int32_t method)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);
	int retrieved_vendor, retrieved_method;

	if (method < kEapMethodMin || method >= kEapMethodMax) {
		const std::string error_msg =
		    "Invalid EAP method: " + std::to_string(method) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	const char *method_str = kEapMethodStrings[method];
	// This string lookup is needed to check if the device supports the
	// corresponding EAP type.
	retrieved_method = eap_peer_get_type(method_str, &retrieved_vendor);
	if (retrieved_vendor == EAP_VENDOR_IETF &&
	    retrieved_method == EAP_TYPE_NONE) {
		const std::string error_msg = "Cannot get EAP method type: " +
					      std::to_string(method) + ".";
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, error_msg.c_str());
	}

	if (wpa_ssid->eap.eap_methods) {
		os_free(wpa_ssid->eap.eap_methods);
	}
	// wpa_supplicant can support setting multiple eap methods for each
	// network. But, this is not really used by Android. So, just adding
	// support for setting one EAP method for each network. The additional
	// |eap_method_type| member in the array is used to indicate the end
	// of list.
	wpa_ssid->eap.eap_methods =
	    (eap_method_type *)os_malloc(sizeof(eap_method_type) * 2);
	if (!wpa_ssid->eap.eap_methods) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	wpa_ssid->eap.eap_methods[0].vendor = retrieved_vendor;
	wpa_ssid->eap.eap_methods[0].method = retrieved_method;
	wpa_ssid->eap.eap_methods[1].vendor = EAP_VENDOR_IETF;
	wpa_ssid->eap.eap_methods[1].method = EAP_TYPE_NONE;

	wpa_ssid->leap = 0;
	wpa_ssid->non_leap = 0;
	if (retrieved_vendor == EAP_VENDOR_IETF &&
	    retrieved_method == EAP_TYPE_LEAP) {
		wpa_ssid->leap++;
	} else {
		wpa_ssid->non_leap++;
	}

	wpa_hexdump(
	    MSG_MSGDUMP, "eap methods", (u8 *)wpa_ssid->eap.eap_methods,
	    sizeof(eap_method_type) * 2);
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

android::binder::Status Network::SetEapPhase2Method(int32_t method)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	if (method < kEapPhase2MethodMin || method >= kEapMethodMax) {
		const std::string error_msg = "Invalid EAP Phase2 method: " +
					      std::to_string(method) + ".";
		return android::binder::Status::fromExceptionCode(
		    android::binder::Status::EX_ILLEGAL_ARGUMENT,
		    error_msg.c_str());
	}
	return setStringFieldAndResetState(
	    kEapPhase2MethodStrings[method], &(wpa_ssid->eap.phase2),
	    "eap phase2");
}

android::binder::Status
Network::SetEapIdentity(const std::vector<uint8_t> &identity)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setByteArrayFieldAndResetState(
	    identity.data(), identity.size(), &(wpa_ssid->eap.identity),
	    &(wpa_ssid->eap.identity_len), "eap identity");
}

android::binder::Status
Network::SetEapAnonymousIdentity(const std::vector<uint8_t> &identity)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setByteArrayFieldAndResetState(
	    identity.data(), identity.size(),
	    &(wpa_ssid->eap.anonymous_identity),
	    &(wpa_ssid->eap.anonymous_identity_len), "eap anonymous_identity");
}

android::binder::Status
Network::SetEapPassword(const std::vector<uint8_t> &password)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	android::binder::Status status = setByteArrayKeyFieldAndResetState(
	    password.data(), password.size(), &(wpa_ssid->eap.password),
	    &(wpa_ssid->eap.password_len), "eap password");
	if (status.isOk()) {
		wpa_ssid->eap.flags &= ~EAP_CONFIG_FLAGS_PASSWORD_NTHASH;
		wpa_ssid->eap.flags &= ~EAP_CONFIG_FLAGS_EXT_PASSWORD;
	}
	return status;
}

android::binder::Status Network::SetEapCACert(const std::string &path)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    path.c_str(), &(wpa_ssid->eap.ca_cert), "eap ca_cert");
}

android::binder::Status Network::SetEapCAPath(const std::string &path)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    path.c_str(), &(wpa_ssid->eap.ca_path), "eap ca_path");
}

android::binder::Status Network::SetEapClientCert(const std::string &path)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    path.c_str(), &(wpa_ssid->eap.client_cert), "eap client_cert");
}

android::binder::Status Network::SetEapPrivateKey(const std::string &path)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    path.c_str(), &(wpa_ssid->eap.private_key), "eap private_key");
}

android::binder::Status Network::SetEapSubjectMatch(const std::string &match)

{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    match.c_str(), &(wpa_ssid->eap.subject_match), "eap subject_match");
}

android::binder::Status Network::SetEapAltSubjectMatch(const std::string &match)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    match.c_str(), &(wpa_ssid->eap.altsubject_match),
	    "eap altsubject_match");
}

android::binder::Status Network::SetEapEngine(bool enable)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	wpa_ssid->eap.engine = enable ? 1 : 0;
	return android::binder::Status::ok();
}

android::binder::Status Network::SetEapEngineID(const std::string &id)

{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    id.c_str(), &(wpa_ssid->eap.engine_id), "eap engine_id");
	return android::binder::Status::ok();
}

android::binder::Status
Network::SetEapDomainSuffixMatch(const std::string &match)

{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	RETURN_IF_NETWORK_INVALID(wpa_ssid);

	return setStringFieldAndResetState(
	    match.c_str(), &(wpa_ssid->eap.domain_suffix_match),
	    "eap domain_suffix_match");
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

/**
 * Reset internal wpa_supplicant state machine state after params update (except
 * bssid).
 */
void Network::resetInternalStateAfterParamsUpdate()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	wpa_sm_pmksa_cache_flush(wpa_s->wpa, wpa_ssid);

	if (wpa_s->current_ssid == wpa_ssid || wpa_s->current_ssid == NULL) {
		/*
		 * Invalidate the EAP session cache if anything in the
		 * current or previously used configuration changes.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}
}

/**
 * Helper function to set value in a string field in |wpa_ssid| structue
 * instance for this network.
 * This function frees any existing data in these fields.
 */
android::binder::Status Network::setStringFieldAndResetState(
    const char *value, uint8_t **to_update_field, const char *hexdump_prefix)
{
	return setStringFieldAndResetState(
	    value, (char **)to_update_field, hexdump_prefix);
}

/**
 * Helper function to set value in a string field in |wpa_ssid| structue
 * instance for this network.
 * This function frees any existing data in these fields.
 */
android::binder::Status Network::setStringFieldAndResetState(
    const char *value, char **to_update_field, const char *hexdump_prefix)
{
	int value_len = strlen(value);
	if (*to_update_field) {
		os_free(*to_update_field);
	}
	*to_update_field = dup_binstr(value, value_len);
	if (!(*to_update_field)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	wpa_hexdump_ascii(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field, value_len);
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

/**
 * Helper function to set value in a string key field in |wpa_ssid| structue
 * instance for this network.
 * This function frees any existing data in these fields.
 */
android::binder::Status Network::setStringKeyFieldAndResetState(
    const char *value, char **to_update_field, const char *hexdump_prefix)
{
	int value_len = strlen(value);
	if (*to_update_field) {
		str_clear_free(*to_update_field);
	}
	*to_update_field = dup_binstr(value, value_len);
	if (!(*to_update_field)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	wpa_hexdump_ascii_key(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field, value_len);
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

/**
 * Helper function to set value in a string field with a corresponding length
 * field in |wpa_ssid| structue instance for this network.
 * This function frees any existing data in these fields.
 */
android::binder::Status Network::setByteArrayFieldAndResetState(
    const uint8_t *value, const size_t value_len, uint8_t **to_update_field,
    size_t *to_update_field_len, const char *hexdump_prefix)
{
	if (*to_update_field) {
		os_free(*to_update_field);
	}
	*to_update_field = (uint8_t *)os_malloc(value_len);
	if (!(*to_update_field)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	os_memcpy(*to_update_field, value, value_len);
	*to_update_field_len = value_len;

	wpa_hexdump_ascii(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field,
	    *to_update_field_len);
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

/**
 * Helper function to set value in a string key field with a corresponding
 * length field in |wpa_ssid| structue instance for this network.
 * This function frees any existing data in these fields.
 */
android::binder::Status Network::setByteArrayKeyFieldAndResetState(
    const uint8_t *value, const size_t value_len, uint8_t **to_update_field,
    size_t *to_update_field_len, const char *hexdump_prefix)
{
	if (*to_update_field) {
		bin_clear_free(*to_update_field, *to_update_field_len);
	}
	*to_update_field = (uint8_t *)os_malloc(value_len);
	if (!(*to_update_field)) {
		return android::binder::Status::fromServiceSpecificError(
		    ERROR_GENERIC, "Memory allocation failed.");
	}
	os_memcpy(*to_update_field, value, value_len);
	*to_update_field_len = value_len;

	wpa_hexdump_ascii_key(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field,
	    *to_update_field_len);
	resetInternalStateAfterParamsUpdate();
	return android::binder::Status::ok();
}

} // namespace wpa_supplicant_binder

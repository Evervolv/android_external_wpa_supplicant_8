/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_NETWORK_H
#define WPA_SUPPLICANT_HIDL_NETWORK_H

#include <android-base/macros.h>

#include "fi/w1/wpa_supplicant/BnNetwork.h"

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "notify.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap.h"
#include "rsn_supp/wpa.h"
}

namespace wpa_supplicant_hidl {

/**
 * Implementation of Network hidl object. Each unique hidl
 * object is used for control operations on a specific network
 * controlled by wpa_supplicant.
 */
class Network : public fi::w1::wpa_supplicant::BnNetwork
{
public:
	Network(
	    struct wpa_global *wpa_global, const char ifname[], int network_id);
	~Network() override = default;

	// Hidl methods exposed in aidl.
	android::hidl::Status GetId(int *network_id_out) override;
	android::hidl::Status GetInterfaceName(
	    std::string *ifname_out) override;
	android::hidl::Status RegisterCallback(
	    const android::sp<fi::w1::wpa_supplicant::INetworkCallback>
		&callback) override;
	android::hidl::Status SetSSID(
	    const std::vector<uint8_t> &ssid) override;
	android::hidl::Status SetBSSID(
	    const std::vector<uint8_t> &bssid) override;
	android::hidl::Status SetScanSSID(bool enable) override;
	android::hidl::Status SetKeyMgmt(int32_t key_mgmt_mask) override;
	android::hidl::Status SetProto(int32_t proto_mask) override;
	android::hidl::Status SetAuthAlg(int32_t auth_alg_mask) override;
	android::hidl::Status SetGroupCipher(
	    int32_t group_cipher_mask) override;
	android::hidl::Status SetPairwiseCipher(
	    int32_t pairwise_cipher_mask) override;
	android::hidl::Status SetPskPassphrase(
	    const std::string &psk) override;
	android::hidl::Status SetWepKey(
	    int key_idx, const std::vector<uint8_t> &wep_key) override;
	android::hidl::Status SetWepTxKeyIdx(int32_t wep_tx_key_idx) override;
	android::hidl::Status SetRequirePMF(bool enable) override;
	android::hidl::Status SetEapMethod(int32_t method) override;
	android::hidl::Status SetEapPhase2Method(int32_t method) override;
	android::hidl::Status SetEapIdentity(
	    const std::vector<uint8_t> &identity) override;
	android::hidl::Status SetEapAnonymousIdentity(
	    const std::vector<uint8_t> &identity) override;
	android::hidl::Status SetEapPassword(
	    const std::vector<uint8_t> &password) override;
	android::hidl::Status SetEapCACert(const std::string &path) override;
	android::hidl::Status SetEapCAPath(const std::string &path) override;
	android::hidl::Status SetEapClientCert(
	    const std::string &path) override;
	android::hidl::Status SetEapPrivateKey(
	    const std::string &path) override;
	android::hidl::Status SetEapSubjectMatch(
	    const std::string &match) override;
	android::hidl::Status SetEapAltSubjectMatch(
	    const std::string &match) override;
	android::hidl::Status SetEapEngine(bool enable) override;
	android::hidl::Status SetEapEngineID(const std::string &id) override;
	android::hidl::Status SetEapDomainSuffixMatch(
	    const std::string &match) override;
	android::hidl::Status GetSSID(std::vector<uint8_t> *ssid) override;
	android::hidl::Status GetBSSID(std::vector<uint8_t> *bssid) override;
	android::hidl::Status GetScanSSID(bool *enable) override;
	android::hidl::Status GetKeyMgmt(int32_t *key_mgmt_mask) override;
	android::hidl::Status GetProto(int32_t *proto_mask) override;
	android::hidl::Status GetAuthAlg(int32_t *auth_alg_mask) override;
	android::hidl::Status GetGroupCipher(
	    int32_t *group_cipher_mask) override;
	android::hidl::Status GetPairwiseCipher(
	    int32_t *pairwise_cipher_mask) override;
	android::hidl::Status GetPskPassphrase(std::string *psk) override;
	android::hidl::Status GetWepKey(
	    int key_idx, std::vector<uint8_t> *wep_key) override;
	android::hidl::Status GetWepTxKeyIdx(
	    int32_t *wep_tx_key_idx) override;
	android::hidl::Status GetRequirePMF(bool *enable) override;
	android::hidl::Status Enable(bool no_connect) override;
	android::hidl::Status Disable() override;
	android::hidl::Status Select() override;
	android::hidl::Status SendNetworkResponse(
	    int type, const std::string &param) override;

private:
	struct wpa_ssid *retrieveNetworkPtr();
	struct wpa_supplicant *retrieveIfacePtr();
	int isPskPassphraseValid(const std::string &psk);
	void resetInternalStateAfterParamsUpdate();
	android::hidl::Status setStringFieldAndResetState(
	    const char *value, uint8_t **to_update_field,
	    const char *hexdump_prefix);
	android::hidl::Status setStringFieldAndResetState(
	    const char *value, char **to_update_field,
	    const char *hexdump_prefix);
	android::hidl::Status setStringKeyFieldAndResetState(
	    const char *value, char **to_update_field,
	    const char *hexdump_prefix);
	android::hidl::Status setByteArrayFieldAndResetState(
	    const uint8_t *value, const size_t value_len,
	    uint8_t **to_update_field, size_t *to_update_field_len,
	    const char *hexdump_prefix);
	android::hidl::Status setByteArrayKeyFieldAndResetState(
	    const uint8_t *value, const size_t value_len,
	    uint8_t **to_update_field, size_t *to_update_field_len,
	    const char *hexdump_prefix);

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global *wpa_global_;
	// Name of the iface this network belongs to.
	const std::string ifname_;
	// Id of the network this hidl object controls.
	const int network_id_;

	DISALLOW_COPY_AND_ASSIGN(Network);
};

}  // namespace wpa_supplicant_hidl

#endif  // WPA_SUPPLICANT_HIDL_NETWORK_H

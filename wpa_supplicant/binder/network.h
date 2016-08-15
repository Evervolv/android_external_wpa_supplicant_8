/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_BINDER_NETWORK_H
#define WPA_SUPPLICANT_BINDER_NETWORK_H

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

namespace wpa_supplicant_binder {

/**
 * Implementation of Network binder object. Each unique binder
 * object is used for control operations on a specific network
 * controlled by wpa_supplicant.
 */
class Network : public fi::w1::wpa_supplicant::BnNetwork
{
public:
	Network(
	    struct wpa_global *wpa_global, const char ifname[], int network_id);
	~Network() override = default;

	// Binder methods exposed in aidl.
	android::binder::Status GetId(int *network_id_out) override;
	android::binder::Status GetInterfaceName(
	    std::string *ifname_out) override;
	android::binder::Status RegisterCallback(
	    const android::sp<fi::w1::wpa_supplicant::INetworkCallback>
		&callback) override;
	android::binder::Status SetSSID(
	    const std::vector<uint8_t> &ssid) override;
	android::binder::Status SetBSSID(
	    const std::vector<uint8_t> &bssid) override;
	android::binder::Status SetScanSSID(bool enable) override;
	android::binder::Status SetKeyMgmt(int32_t key_mgmt_mask) override;
	android::binder::Status SetProto(int32_t proto_mask) override;
	android::binder::Status SetAuthAlg(int32_t auth_alg_mask) override;
	android::binder::Status SetGroupCipher(
	    int32_t group_cipher_mask) override;
	android::binder::Status SetPairwiseCipher(
	    int32_t pairwise_cipher_mask) override;
	android::binder::Status SetPskPassphrase(
	    const std::string &psk) override;
	android::binder::Status SetWepKey(
	    int key_idx, const std::vector<uint8_t> &wep_key) override;
	android::binder::Status SetWepTxKeyIdx(int32_t wep_tx_key_idx) override;
	android::binder::Status SetRequirePMF(bool enable) override;
	android::binder::Status SetEapMethod(int32_t method) override;
	android::binder::Status SetEapPhase2Method(int32_t method) override;
	android::binder::Status SetEapIdentity(
	    const std::vector<uint8_t> &identity) override;
	android::binder::Status SetEapAnonymousIdentity(
	    const std::vector<uint8_t> &identity) override;
	android::binder::Status SetEapPassword(
	    const std::vector<uint8_t> &password) override;
	android::binder::Status SetEapCACert(const std::string &path) override;
	android::binder::Status SetEapCAPath(const std::string &path) override;
	android::binder::Status SetEapClientCert(
	    const std::string &path) override;
	android::binder::Status SetEapPrivateKey(
	    const std::string &path) override;
	android::binder::Status SetEapSubjectMatch(
	    const std::string &match) override;
	android::binder::Status SetEapAltSubjectMatch(
	    const std::string &match) override;
	android::binder::Status SetEapEngine(bool enable) override;
	android::binder::Status SetEapEngineID(const std::string &id) override;
	android::binder::Status SetEapDomainSuffixMatch(
	    const std::string &match) override;
	android::binder::Status GetSSID(std::vector<uint8_t> *ssid) override;
	android::binder::Status GetBSSID(std::vector<uint8_t> *bssid) override;
	android::binder::Status GetScanSSID(bool *enable) override;
	android::binder::Status GetKeyMgmt(int32_t *key_mgmt_mask) override;
	android::binder::Status GetProto(int32_t *proto_mask) override;
	android::binder::Status GetAuthAlg(int32_t *auth_alg_mask) override;
	android::binder::Status GetGroupCipher(
	    int32_t *group_cipher_mask) override;
	android::binder::Status GetPairwiseCipher(
	    int32_t *pairwise_cipher_mask) override;
	android::binder::Status GetPskPassphrase(std::string *psk) override;
	android::binder::Status GetWepKey(
	    int key_idx, std::vector<uint8_t> *wep_key) override;
	android::binder::Status GetWepTxKeyIdx(
	    int32_t *wep_tx_key_idx) override;
	android::binder::Status GetRequirePMF(bool *enable) override;
	android::binder::Status Enable(bool no_connect) override;
	android::binder::Status Disable() override;
	android::binder::Status Select() override;

private:
	struct wpa_ssid *retrieveNetworkPtr();
	struct wpa_supplicant *retrieveIfacePtr();
	int isPskPassphraseValid(const std::string &psk);
	void resetInternalStateAfterParamsUpdate();
	android::binder::Status setStringFieldAndResetState(
	    const char *value, uint8_t **to_update_field,
	    const char *hexdump_prefix);
	android::binder::Status setStringFieldAndResetState(
	    const char *value, char **to_update_field,
	    const char *hexdump_prefix);
	android::binder::Status setStringKeyFieldAndResetState(
	    const char *value, char **to_update_field,
	    const char *hexdump_prefix);
	android::binder::Status setByteArrayFieldAndResetState(
	    const uint8_t *value, const size_t value_len,
	    uint8_t **to_update_field, size_t *to_update_field_len,
	    const char *hexdump_prefix);
	android::binder::Status setByteArrayKeyFieldAndResetState(
	    const uint8_t *value, const size_t value_len,
	    uint8_t **to_update_field, size_t *to_update_field_len,
	    const char *hexdump_prefix);

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	const struct wpa_global *wpa_global_;
	// Name of the iface this network belongs to.
	const std::string ifname_;
	// Id of the network this binder object controls.
	const int network_id_;

	DISALLOW_COPY_AND_ASSIGN(Network);
};

}  // namespace wpa_supplicant_binder

#endif  // WPA_SUPPLICANT_BINDER_NETWORK_H

/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package fi.w1.wpa_supplicant;

import fi.w1.wpa_supplicant.INetworkCallback;

/**
 * Interface exposed by wpa_supplicant for each network configuration it controls.
 * A network is wpa_supplicant's way of representing the configuration parameters of a Wifi
 * service set. Service sets are identified by their service set identitifier (SSID).
 * The parameters for a network includes the credentials, bssid, etc.
 */
@utf8InCpp
interface INetwork {
	/* Non-specific error encountered */
	const int ERROR_GENERIC = 1;
	/* Network is no longer valid */
	const int ERROR_NETWORK_INVALID = 2;

	/**
	 * Constants used in Set/Get network params.
	 */
	/** Max length of SSID param. */
	const int SSID_MAX_LEN = 32;

	/** Length of BSSID param. */
	const int BSSID_LEN = 6;

	/** Min length of PSK passphrase param. */
	const int PSK_PASSPHRASE_MIN_LEN = 8;

	/** Max length of PSK passphrase param. */
	const int PSK_PASSPHRASE_MAX_LEN = 63;

	/** Max number of WEP keys param. */
	const int WEP_KEYS_MAX_NUM = 4;

	/** Length of each WEP40 keys param. */
	const int WEP40_KEY_LEN = 5;
	/** Length of each WEP104 keys param. */
	const int WEP104_KEY_LEN = 13;

	/** Possble mask of values for KeyMgmt param. */
	const int KEY_MGMT_MASK_WPA_EAP = 0x01;
	const int KEY_MGMT_MASK_WPA_PSK = 0x02;
	const int KEY_MGMT_MASK_NONE = 0x04;
	const int KEY_MGMT_MASK_IEEE8021X = 0x08;

	/** Possble mask of values for Proto param. */
	const int PROTO_MASK_WPA = 0x01;
	const int PROTO_MASK_RSN = 0x02;
	const int PROTO_MASK_OSEN = 0x08;

	/** Possble mask of values for AuthAlg param. */
	const int AUTH_ALG_MASK_OPEN = 0x01;
	const int AUTH_ALG_MASK_SHARED = 0x02;
	const int AUTH_ALG_MASK_LEAP = 0x04;

	/** Possble mask of values for GroupCipher param. */
	const int GROUP_CIPHER_MASK_WEP40 = 0x02;
	const int GROUP_CIPHER_MASK_WEP104 = 0x04;
	const int GROUP_CIPHER_MASK_TKIP = 0x08;
	const int GROUP_CIPHER_MASK_CCMP = 0x10;

	/** Possble mask of values for PairwiseCipher param. */
	const int PAIRWISE_CIPHER_MASK_NONE = 0x01;
	const int PAIRWISE_CIPHER_MASK_TKIP = 0x08;
	const int PAIRWISE_CIPHER_MASK_CCMP = 0x10;

	/** Possble mask of values for EapMethod param. */
	const int EAP_METHOD_PEAP = 0;
	const int EAP_METHOD_TLS = 1;
	const int EAP_METHOD_TTLS = 2;
	const int EAP_METHOD_PWD = 3;
	const int EAP_METHOD_SIM = 4;
	const int EAP_METHOD_AKA = 5;
	const int EAP_METHOD_AKA_PRIME = 6;
	const int EAP_METHOD_WFA_UNAUTH_TLS = 7;

	/** Possble mask of values for Phase2Method param. */
	const int EAP_PHASE2_METHOD_NONE = 0;
	const int EAP_PHASE2_METHOD_PAP = 1;
	const int EAP_PHASE2_METHOD_MSPAP = 2;
	const int EAP_PHASE2_METHOD_MSPAPV2 = 3;
	const int EAP_PHASE2_METHOD_GTC = 4;

	/**
	 * Retrieves the ID allocated to this network by wpa_supplicant.
	 *
	 * This is not the |SSID| of the network, but an internal identifier for
	 * this network used by wpa_supplicant.
	 *
	 * @return network ID.
	 */
	int GetId();

	/**
	 * Retrieves the name of the interface this network belongs to.
	 *
	 * @return Name of the network interface, e.g., wlan0
	 */
	String GetInterfaceName();

	/**
	 * Register for callbacks from this network.
	 *
	 * These callbacks are invoked for events that are specific to this network.
	 *
	 * @param callback Binder object reference to a |INetworkCallback|
	 *        instance.
	 */
	void RegisterCallback(in INetworkCallback callback);

	/**
	 * Setters for the various network params.
	 * These correspond to elements of |wpa_sssid| struct used internally by
	 * wpa_supplicant to represent each network.
	 * Sets |{struct wpa_ssid}.ssid|.
	 */
	/** Set SSID for this network. Max length of |SSID_MAX_LEN|. */
	void SetSSID(in byte[] ssid);

	/**
	 * Set the network to only connect to an AP with provided BSSSID.
	 * Pass array of size 0 to clear this param.
	 * Length of the value should be |BSSID_LEN|.
	 * Sets |{struct wpa_ssid}.bssid|.
	 */
	void SetBSSID(in byte[] bssid);

	/**
	 * Set whether to send Probe Requests for this network (hidden).
	 * Sets |{struct wpa_ssid}.scan_ssid|.
	 */
	void SetScanSSID(boolean enable);

	/**
	 * Combination of |KEY_MGMT_MASK_*| values above.
	 * Sets |{struct wpa_ssid}.key_mgmt|.
	 */
	void SetKeyMgmt(int key_mgmt_mask);

	/**
	 * Combination of |PROTO_MASK_*| values above.
	 * Sets |{struct wpa_ssid}.proto|.
	 */
	void SetProto(int proto_mask);

	/**
	 * Combination of |AUTH_ALG_MASK_*| values above.
	 * Sets |{struct wpa_ssid}.auth_alg|.
	 * */
	void SetAuthAlg(int auth_alg_mask);

	/**
	 * Combination of |GROUP_CIPHER_MASK_*| values above.
	 * Sets |{struct wpa_ssid}.group_cipher|.
	 */
	void SetGroupCipher(int group_cipher_mask);

	/**
	 * Combination of |PAIRWISE_CIPHER_MASK_*| values above.
	 * Sets |{struct wpa_ssid}.pairwise_cipher|.
	 * */
	void SetPairwiseCipher(int pairwise_cipher_mask);

	/**
	 * Set passphrase for WPA_PSK network.
	 * Min length of value is |PSK_PASSPHRASE_MIN_LEN|.
	 * Max length of value is |PSK_PASSPHRASE_MAX_LEN|.
	 * Sets |{struct wpa_ssid}.passphrase|.
	 */
	void SetPskPassphrase(String psk);

	/**
	 * Set WEP key for WEP network.
	 * Length of each key should be either |WEP40_KEY_LEN| or
	 * |WEP104_KEY_LEN|.
	 * Sets |{struct wpa_ssid}.wep_key|.
	 *
	 * @param key_idx Index of wep key to be set.
	 *                Max of |WEP_KEYS_MAX_NUM| keys.
	 */
	void SetWepKey(int key_idx, in byte[] wep_key);

	/**
	 * Set default Tx key index for WEP network.
	 * Sets |{struct wpa_ssid}.wep_tx_key_idx|.
	 * */
	void SetWepTxKeyIdx(int wep_tx_key_idx);

	/**
	 * Set whether RequirePMF is enabled for this network.
	 * Sets |{struct wpa_ssid}.ieee80211w|.
	 * */
	void SetRequirePMF(boolean enable);

	/**
	 * Set EAP Method for this network.
	 * Must be one of |EAP_METHOD_*| values.
	 * Sets |{struct eap_peer_config}.eap_methods|.
	 */
	void SetEapMethod(int method);

	/**
	 * Set EAP Phase2 Method for this network.
	 * Must be one of |EAP_PHASE2_METHOD_*| values.
	 * Sets |{struct eap_peer_config}.phase2|.
	 */
	void SetEapPhase2Method(int method);

	/**
	 * Set EAP Identity for this network.
	 * Sets |{struct eap_peer_config}.identity|.
	 */
	void SetEapIdentity(in byte[] identity);

	/**
	 * Set EAP Anonymous Identity for this network.
	 * Sets |{struct eap_peer_config}.anonymous_identity|.
	 */
	void SetEapAnonymousIdentity(in byte[] identity);

	/**
	 * Set EAP Password for this network.
	 * Sets |{struct eap_peer_config}.password|.
	 */
	void SetEapPassword(in byte[] password);

	/**
	 * Set EAP CA certificate file path for this network.
	 * Sets |{struct eap_peer_config}.ca_cert|.
	 */
	void SetEapCACert(String path);

	/**
	 * Set EAP CA certificate directory path for this network.
	 * Sets |{struct eap_peer_config}.ca_path|.
	 */
	void SetEapCAPath(String path);

	/**
	 * Set EAP Client certificate file path for this network.
	 * Sets |{struct eap_peer_config}.client_cert|.
	 */
	void SetEapClientCert(String path);

	/**
	 * Set EAP private key file path for this network.
	 * Sets |{struct eap_peer_config}.private_key|.
	 */
	void SetEapPrivateKey(String path);

	/**
	 * Set EAP subject match for this network.
	 * Sets |{struct eap_peer_config}.subject_match|.
	 */
	void SetEapSubjectMatch(String match);

	/**
	 * Set EAP Altsubject match for this network.
	 * Sets |{struct eap_peer_config}.altsubject_match|.
	 */
	void SetEapAltSubjectMatch(String match);

	/**
	 * Enable EAP Open SSL Engine for this network.
	 * Sets |{struct eap_peer_config}.engine|.
	 */
	void SetEapEngine(boolean enable);

	/**
	 * Set EAP Open SSL Engine ID for this network.
	 * Sets |{struct eap_peer_config}.engine_id|.
	 */
	void SetEapEngineID(String id);

	/**
	 * Set EAP Domain suffix match for this network.
	 * Sets |{struct eap_peer_config}.domain_suffix_match|.
	 */
	void SetEapDomainSuffixMatch(String match);

	/**
	 * Getters for the various network params.
	 */
	/** Get SSID for this network. */
	byte[] GetSSID();

	/** Get the BSSID set for this network. */
	byte[] GetBSSID();

	/** Get whether Probe Requests are being sent for this network (hidden). */
	boolean GetScanSSID();

	/** Combination of |KEY_MGMT_MASK_*| values above. */
	int GetKeyMgmt();

	/** Combination of |PROTO_MASK_*| values above. */
	int GetProto();

	/** Combination of |AUTH_ALG_MASK_*| values above. */
	int GetAuthAlg();

	/** Combination of |GROUP_CIPHER_MASK_*| values above. */
	int GetGroupCipher();

	/** Combination of |PAIRWISE_CIPHER_MASK_*| values above. */
	int GetPairwiseCipher();

	/** Get passphrase for WPA_PSK network. */
	String GetPskPassphrase();

	/**
	 * Get WEP key for WEP network.
	 *
	 * @param key_idx Index of wep key to be fetched.
	 *                Max of |WEP_KEYS_MAX_NUM| keys.
	 */
	byte[] GetWepKey(int key_idx);

	/** Get default Tx key index for WEP network. */
	int GetWepTxKeyIdx();

	/** Get whether RequirePMF is enabled for this network. */
	boolean GetRequirePMF();

	/**
	 * Enable the network for connection purposes.
	 *
	 * This may trigger a connection to the network.
	 *
	 * @param no_connect Only enable the network, dont trigger a connect.
	 */
	void Enable(boolean no_connect);

	/**
	 * Disable the network for connection purposes.
	 *
	 * This may trigger a disconnection from the network, if currently
	 * connected to this network.
	 */
	void Disable();

	/**
	 * Initiate connection to this network.
	 */
	void Select();
}

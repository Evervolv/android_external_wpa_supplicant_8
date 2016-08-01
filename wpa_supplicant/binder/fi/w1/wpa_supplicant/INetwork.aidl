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
	 */
	/** Set SSID for this network. Max length of |SSID_MAX_LEN|. */
	void SetSSID(in byte[] ssid);

	/**
	 * Set the network to only connect to an AP with provided BSSSID.
	 * Pass array of size 0 to clear this param.
	 * Length of the value should be |BSSID_LEN|.
	 */
	void SetBSSID(in byte[] bssid);

	/** Set whether to send Probe Requests for this network (hidden). */
	void SetScanSSID(boolean enable);

	/** Combination of |KEY_MGMT_MASK_*| values above. */
	void SetKeyMgmt(int key_mgmt_mask);

	/** Combination of |PROTO_MASK_*| values above. */
	void SetProto(int proto_mask);

	/** Combination of |AUTH_ALG_MASK_*| values above. */
	void SetAuthAlg(int auth_alg_mask);

	/** Combination of |GROUP_CIPHER_MASK_*| values above. */
	void SetGroupCipher(int group_cipher_mask);

	/** Combination of |PAIRWISE_CIPHER_MASK_*| values above. */
	void SetPairwiseCipher(int pairwise_cipher_mask);

	/**
	 * Set passphrase for WPA_PSK network.
	 * Min length of value is |PSK_PASSPHRASE_MIN_LEN|.
	 * Max length of value is |PSK_PASSPHRASE_MAX_LEN|.
	 */
	void SetPskPassphrase(String psk);

	/**
	 * Set WEP key for WEP network.
	 * Length of each key should be either |WEP40_KEY_LEN| or
	 * |WEP104_KEY_LEN|.
	 *
	 * @param key_idx Index of wep key to be set.
	 *                Max of |WEP_KEYS_MAX_NUM| keys.
	 */
	void SetWepKey(int key_idx, in byte[] wep_key);

	/** Set default Tx key index for WEP network. */
	void SetWepTxKeyIdx(int wep_tx_key_idx);

	/** Set whether RequirePMF is enabled for this network. */
	void SetRequirePMF(boolean enable);

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

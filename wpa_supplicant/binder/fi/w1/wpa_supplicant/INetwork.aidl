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
}

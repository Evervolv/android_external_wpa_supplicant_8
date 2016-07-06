/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package fi.w1.wpa_supplicant;

/**
 * Interface exposed by wpa_supplicant for each network interface it controls.
 */
@utf8InCpp
interface IIface {
	/* Error values returned by the service to RPC method calls. */
	const int ERROR_INVALID_ARGS = 1;
	const int ERROR_UNKNOWN = 2;
	const int ERROR_IFACE_UNKNOWN = 3;

	/**
	 * Retrieves the name of the iface this object controls.
	 *
	 * @return Name of the network interface, e.g., wlan0
	 */
	String GetName();
}

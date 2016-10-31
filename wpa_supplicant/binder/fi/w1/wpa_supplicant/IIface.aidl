/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package fi.w1.wpa_supplicant;

import fi.w1.wpa_supplicant.INetwork;

/**
 * Interface exposed by wpa_supplicant for each network interface it controls.
 */
@utf8InCpp
interface IIface {
	/* Non-specific error encountered */
	const int ERROR_GENERIC = 1;
	/* Iface is no longer valid */
	const int ERROR_IFACE_INVALID = 2;

	/**
	 * Retrieves the name of the network interface.
	 *
	 * @return Name of the network interface, e.g., wlan0
	 */
	String GetName();

	/**
	 * Add a new network to the interface.
	 *
	 * @return Binder object representing the new network.
	 */
	INetwork AddNetwork();

	/**
	 * Remove a network from the interface.
	 *
	 * Use |INetwork.GetId()| on the corresponding network binder object
	 * to retrieve the ID.
	 *
	 * @param id Network ID allocated to the corresponding network.
	 */
	void RemoveNetwork(in int id);
}

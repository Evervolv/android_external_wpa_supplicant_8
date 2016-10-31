/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package fi.w1.wpa_supplicant;

import fi.w1.wpa_supplicant.IIfaceCallback;
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
	/* Iface is currently disabled */
	const int ERROR_IFACE_DISABLED = 3;
	/* Iface is currently connected */
	const int ERROR_IFACE_NOT_DISCONNECTED = 4;
	/* Network being removed/retrieved does not exist */
	const int ERROR_NETWORK_UNKNOWN = 5;

	/** Length of mac_address param in |InitiateTDLS|* functions. */
	const int MAC_ADDRESS_LEN = 6;

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

	/**
	 * Gets a binder object for the network corresponding to the network_id.
	 *
	 * Use |INetwork.GetId()| on the corresponding network binder object
	 * to retrieve the ID.
	 *
	 * @param id Network ID allocated to the corresponding network.
	 *
	 * @return Binder object representing the network.
	 */
	INetwork GetNetwork(in int id);

	/**
	 * Register for callbacks from this interface.
	 *
	 * These callbacks are invoked for events that are specific to this interface.
	 *
	 * @param callback Binder object reference to a |IIfaceCallback|
	 *        instance.
	 */
	void RegisterCallback(in IIfaceCallback callback);

	/**
	 * Reconnect to the currently active network, even if we are already
	 * connected.
	 */
	void Reassociate();

	/**
	 * Reconnect to the currently active network, if we are currently
	 * disconnected.
	 */
	void Reconnect();

	/**
	 * Disconnect from the current active network.
	 */
	void Disconnect();

	/**
	 * Turn on/off power save mode for the interface.
	 *
	 * @param enable Indicate if power save is to be turned on/off.
	 */
	void SetPowerSave(boolean enable);

	/**
	 * Initiate TDLS discover with the provided peer mac address.
	 *
	 * @param mac_address MAC address of the peer.
	 */
	void InitiateTDLSDiscover(in byte[] mac_address);

	/**
	 * Initiate TDLS setup with the provided peer mac address.
	 *
	 * @param mac_address MAC address of the peer.
	 */
	void InitiateTDLSSetup(in byte[] mac_address);

	/**
	 * Initiate TDLS teardown with the provided peer mac address.
	 *
	 * @param mac_address MAC address of the peer.
	 */
	void InitiateTDLSTeardown(in byte[] mac_address);
}

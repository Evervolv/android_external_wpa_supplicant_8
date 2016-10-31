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
 * Callback Interface exposed by the wpa_supplicant service
 * for each interface (IIface).
 *
 * Clients need to host an instance of this binder object and
 * pass a reference of the object to wpa_supplicant via the
 * corresponding |IIface.registerCallback| method.
 */
@utf8InCpp
interface IIfaceCallback {
	/** Used to indicate a non specific network event via |OnStateChanged|.*/
	const int NETWORK_ID_INVALID = -1;

	/** Various states of the interface reported by |OnStateChanged|.*/
	/**
	 * STATE_DISCONNECTED - Disconnected state
	 *
	 * This state indicates that client is not associated, but is likely to
	 * start looking for an access point. This state is entered when a
	 * connection is lost.
	 */
	const int STATE_DISCONNECTED = 0;
	/**
	 * STATE_INTERFACE_DISABLED - Interface disabled
	 *
	 * This state is entered if the network interface is disabled, e.g.,
	 * due to rfkill. wpa_supplicant refuses any new operations that would
	 * use the radio until the interface has been enabled.
	 */
	const int STATE_INTERFACE_DISABLED = 1;
	/**
	 * STATE_INACTIVE - Inactive state (wpa_supplicant disabled)
	 *
	 * This state is entered if there are no enabled networks in the
	 * configuration. wpa_supplicant is not trying to associate with a new
	 * network and external interaction (e.g., ctrl_iface call to add or
	 * enable a network) is needed to start association.
	 */
	const int STATE_INACTIVE = 2;
	/**
	 * STATE_SCANNING - Scanning for a network
	 *
	 * This state is entered when wpa_supplicant starts scanning for a
	 * network.
	 */
	const int STATE_SCANNING = 3;
	/**
	 * STATE_AUTHENTICATING - Trying to authenticate with a BSS/SSID
	 *
	 * This state is entered when wpa_supplicant has found a suitable BSS
	 * to authenticate with and the driver is configured to try to
	 * authenticate with this BSS. This state is used only with drivers
	 * that use wpa_supplicant as the SME.
	 */
	const int STATE_AUTHENTICATING = 4;
	/**
	 * STATE_ASSOCIATING - Trying to associate with a BSS/SSID
	 *
	 * This state is entered when wpa_supplicant has found a suitable BSS
	 * to associate with and the driver is configured to try to associate
	 * with this BSS in ap_scan=1 mode. When using ap_scan=2 mode, this
	 * state is entered when the driver is configured to try to associate
	 * with a network using the configured SSID and security policy.
	 */
	const int STATE_ASSOCIATING = 5;
	/**
	 * STATE_ASSOCIATED - Association completed
	 *
	 * This state is entered when the driver reports that association has
	 * been successfully completed with an AP. If IEEE 802.1X is used
	 * (with or without WPA/WPA2), wpa_supplicant remains in this state
	 * until the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	const int STATE_ASSOCIATED = 6;
	/**
	 * STATE_4WAY_HANDSHAKE - WPA 4-Way Key Handshake in progress
	 *
	 * This state is entered when WPA/WPA2 4-Way Handshake is started. In
	 * case of WPA-PSK, this happens when receiving the first EAPOL-Key
	 * frame after association. In case of WPA-EAP, this state is entered
	 * when the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	const int STATE_4WAY_HANDSHAKE = 7;
	/**
	 * STATE_GROUP_HANDSHAKE - WPA Group Key Handshake in progress
	 *
	 * This state is entered when 4-Way Key Handshake has been completed
	 * (i.e., when the supplicant sends out message 4/4) and when Group
	 * Key rekeying is started by the AP (i.e., when supplicant receives
	 * message 1/2).
	 */
	const int STATE_GROUP_HANDSHAKE = 8;
	/**
	 * STATE_COMPLETED - All authentication completed
	 *
	 * This state is entered when the full authentication process is
	 * completed. In case of WPA2, this happens when the 4-Way Handshake is
	 * successfully completed. With WPA, this state is entered after the
	 * Group Key Handshake; with IEEE 802.1X (non-WPA) connection is
	 * completed after dynamic keys are received (or if not used, after
	 * the EAP authentication has been completed). With static WEP keys and
	 * plaintext connections, this state is entered when an association
	 * has been completed.
	 *
	 * This state indicates that the supplicant has completed its
	 * processing for the association phase and that data connection is
	 * fully configured.
	 */
	const int STATE_COMPLETED = 9;

	/**
	 * Used to indicate that a new network has been added.
	 *
	 * @param id Network ID allocated to the corresponding network.
	 */
	oneway void OnNetworkAdded(int id);

	/**
	 * Used to indicate that a network has been removed.
	 *
	 * @param id Network ID allocated to the corresponding network.
	 */
	oneway void OnNetworkRemoved(int id);

	/**
	 * Used to indicate a state change event on this particular iface. This
	 * event may be triggered by a particular network in which case the
	 * |network_id|, |ssid|, |bssid| parameters will indicate the parameters
	 * of the network/AP which cased this state transition.
	 *
	 * @param new_state New State of the interface.  This will be one of
	 *        the |STATE_|* values above.
	 * @param bssid BSSID of the corresponding AP which caused this state
	 *        change event. This will be empty if this event is not specific
	 *        to a particular network.
	 * @param network_id ID of the corresponding network which caused this
	 *        state change event. This will be |INVALID_NETWORK_ID| if this
	 *        event is not specific to a particular network.
	 * @param ssid SSID of the corresponding network which caused this state
	 *        change event. This will be empty if this event is not specific
	 *        to a particular network.
	 */
	oneway void OnStateChanged(
	    int new_state, in byte[] bssid, int network_id, in byte[] ssid);
}

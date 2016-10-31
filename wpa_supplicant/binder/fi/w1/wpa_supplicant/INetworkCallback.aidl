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
 * for each network (INetwork).
 *
 * Clients need to host an instance of this binder object and
 * pass a reference of the object to wpa_supplicant via the
 * corresponding |INetwork.registerCallback| method.
 */
@utf8InCpp
interface INetworkCallback {
	/** Various request types received for the network from |OnNetworkRequest|.*/
	const int NETWORK_REQ_UNKNOWN = 0;
	const int NETWORK_REQ_EAP_IDENTITY = 1;
	const int NETWORK_REQ_EAP_PASSWORD = 2;
	const int NETWORK_REQ_EAP_NEW_PASSWORD = 3;
	const int NETWORK_REQ_EAP_PIN = 4;
	const int NETWORK_REQ_EAP_OTP = 5;
	const int NETWORK_REQ_EAP_PASSPHRASE = 6;
	const int NETWORK_REQ_SIM = 7;
	const int NETWORK_REQ_PSK_PASSPHRASE = 8;
	const int NETWORK_REQ_EXT_CERT_CHECK = 9;

	/**
	 * Used to indicate a request on this particular network. The type of
	 * request is one of the |NETWORK_REQ_| values above and depending on
	 * the request type may include additional params.
	 *
	 * The response for the request must be sent using the corresponding
	 * |INetwork.SendNetworkResponse| call.
	 *
	 * @param type Type of request. This will be one of the |NETWORK_REQ_|*
	 *        values above.
	 * @param param Additional param associated with the request.
	 *        For ex: NETWORK_REQ_SIM request type may contain either
	 *        "GSM-AUTH" or "UMTS-AUTH" param to indicate the need for
	 *        external GSM or 3G authentication.
	 */
	oneway void OnNetworkRequest(int type, String param);
}

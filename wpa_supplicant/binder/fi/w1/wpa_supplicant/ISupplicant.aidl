/*
 * WPA Supplicant - binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package fi.w1.wpa_supplicant;

import fi.w1.wpa_supplicant.ParcelableIfaceParams;
import fi.w1.wpa_supplicant.ISupplicantCallback;
import fi.w1.wpa_supplicant.IIface;

/**
 * Interface exposed by the wpa_supplicant binder service registered
 * with the service manager with name: wpa_supplicant.
 */
@utf8InCpp
interface ISupplicant {
	/* Non-specific error encountered */
	const int ERROR_GENERIC = 1;
	/* Iface being added already exists */
	const int ERROR_IFACE_EXISTS = 2;
	/* Iface being removed/retrieved does not exist */
	const int ERROR_IFACE_UNKNOWN = 3;

	/**
	 * Debug levels for wpa_supplicant.
	 * These correspond to levels defined in |wpa_debug.h|.
	 */
	const int DEBUG_LEVEL_EXCESSIVE = 1;
	const int DEBUG_LEVEL_MSGDUMP = 2;
	const int DEBUG_LEVEL_DEBUG = 3;
	const int DEBUG_LEVEL_INFO = 4;
	const int DEBUG_LEVEL_WARNING = 5;
	const int DEBUG_LEVEL_ERROR = 6;

	/**
	 * Registers a wireless interface in wpa_supplicant.
	 *
	 * @param params Instance of |ParcelableIfaceParams| containing the
	 *        parameters of the interface.
	 *
	 * @return Binder object representing the interface.
	 */
	IIface CreateInterface(in ParcelableIfaceParams params);

	/**
	 * Deregisters a wireless interface from wpa_supplicant.
	 *
	 * @param ifname Name of the network interface, e.g., wlan0
	 */
	void RemoveInterface(in String ifname);

	/**
	 * Gets a binder object for the interface corresponding to ifname
	 * which wpa_supplicant already controls.
	 *
	 * @param ifname Name of the network interface, e.g., wlan0
	 *
	 * @return Binder object representing the interface.
	 */
	IIface GetInterface(in String ifname);

	/**
	 * Set debug parameters for wpa_supplicant.
	 *
	 * @param level Debug logging level for wpa_supplicant.
	 *        (one of DEBUG_LEVEL_* values).
	 * @param timestamp Determines whether to show timestamps in logs or
	 *        not.
	 * @param show_keys Determines whether to show keys in debug logs or
	 *        not.
	 *        CAUTION: Do not set this param in production code!
	 */
	void SetDebugParams(
	    int level, boolean show_timestamp, boolean show_keys);

	/**
	 * Get the debug level set.
	 *
	 * @return one of DEBUG_LEVEL_* values.
	 */
	int GetDebugLevel();

	/**
	 * Get whether the |show_timestamp| parameter has been set ot not.
	 *
	 * @return true if set, false otherwise.
	 */
	boolean GetDebugShowTimestamp();

	/**
	 * Get whether the |show_keys| parameter has been set ot not.
	 *
	 * @return true if set, false otherwise.
	 */
	boolean GetDebugShowKeys();

	/**
	 * Register for callbacks from the wpa_supplicant service.
	 *
	 * These callbacks are invoked for global events that are not specific
	 * to any interface or network.
	 *
	 * @param callback Binder object reference to a |ISupplicantCallback|
	 *        instance.
	 */
	void RegisterCallback(in ISupplicantCallback callback);
}

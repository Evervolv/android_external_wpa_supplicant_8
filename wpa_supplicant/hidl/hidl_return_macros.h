/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

// Macros to invoke the _hidl_cb to return status along with any return values.
#define HIDL_RETURN(status_code, ...)                         \
	do {                                                  \
		SupplicantStatus status{.code = status_code}; \
		_hidl_cb(status, ##__VA_ARGS__);              \
		return Void();                                \
	} while (false)

/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <hwbinder/IPCThreadState.h>
#include <hwbinder/ProcessState.h>

#include "hidl_manager.h"

extern "C" {
#include "hidl.h"
#include "hidl_i.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/includes.h"
}

using android::hardware::ProcessState;
using android::hardware::IPCThreadState;
using android::hardware::wifi::supplicant::V1_0::implementation::HidlManager;

void wpas_hidl_sock_handler(
    int /* sock */, void * /* eloop_ctx */, void *sock_ctx)
{
	struct wpas_hidl_priv *priv = (wpas_hidl_priv *)sock_ctx;
	wpa_printf(MSG_DEBUG, "Processing hidl events on FD %d", priv->hidl_fd);
	IPCThreadState::self()->handlePolledCommands();
}

struct wpas_hidl_priv *wpas_hidl_init(struct wpa_global *global)
{
	struct wpas_hidl_priv *priv;
	HidlManager *hidl_manager;

	priv = (wpas_hidl_priv *)os_zalloc(sizeof(*priv));
	if (!priv)
		return NULL;
	priv->global = global;

	wpa_printf(MSG_DEBUG, "Initing hidl control");

	ProcessState::self()->setThreadPoolMaxThreadCount(0);
	IPCThreadState::self()->disableBackgroundScheduling(true);
	IPCThreadState::self()->setupPolling(&priv->hidl_fd);
	if (priv->hidl_fd < 0)
		goto err;

	wpa_printf(MSG_INFO, "Processing hidl events on FD %d", priv->hidl_fd);
	// Look for read events from the hidl socket in the eloop.
	if (eloop_register_read_sock(
		priv->hidl_fd, wpas_hidl_sock_handler, global, priv) < 0)
		goto err;

	hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		goto err;
	hidl_manager->registerHidlService(global);
	// We may not need to store this hidl manager reference in the
	// global data strucure because we've made it a singleton class.
	priv->hidl_manager = (void *)hidl_manager;

	return priv;
err:
	wpas_hidl_deinit(priv);
	return NULL;
}

void wpas_hidl_deinit(struct wpas_hidl_priv *priv)
{
	if (!priv)
		return;

	wpa_printf(MSG_DEBUG, "Deiniting hidl control");

	HidlManager::destroyInstance();
	eloop_unregister_read_sock(priv->hidl_fd);
	IPCThreadState::shutdown();
	os_free(priv);
}

int wpas_hidl_register_interface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->hidl)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Registering interface to hidl control: %s",
	    wpa_s->ifname);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->registerInterface(wpa_s);
}

int wpas_hidl_unregister_interface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->hidl)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Deregistering interface from hidl control: %s",
	    wpa_s->ifname);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->unregisterInterface(wpa_s);
}

int wpas_hidl_register_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !wpa_s->global->hidl || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Registering network to hidl control: %d", ssid->id);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->registerNetwork(wpa_s, ssid);
}

int wpas_hidl_unregister_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !wpa_s->global->hidl || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Deregistering network from hidl control: %d", ssid->id);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->unregisterNetwork(wpa_s, ssid);
}

int wpas_hidl_notify_state_changed(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->hidl)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Notifying state change event to hidl control: %d",
	    wpa_s->wpa_state);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->notifyStateChange(wpa_s);
}

int wpas_hidl_notify_network_request(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
    enum wpa_ctrl_req_type rtype, const char *default_txt)
{
	if (!wpa_s || !wpa_s->global->hidl || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Notifying network request to hidl control: %d",
	    ssid->id);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return 1;

	return hidl_manager->notifyNetworkRequest(
	    wpa_s, ssid, rtype, default_txt);
}

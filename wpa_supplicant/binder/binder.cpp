/*
 * binder interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

#include "binder_manager.h"

extern "C" {
#include "binder.h"
#include "binder_i.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/includes.h"
}

void wpas_binder_sock_handler(
    int /* sock */, void * /* eloop_ctx */, void *sock_ctx)
{
	struct wpas_binder_priv *priv = (wpas_binder_priv *)sock_ctx;
	wpa_printf(
	    MSG_DEBUG, "Processing binder events on FD %d", priv->binder_fd);
	android::IPCThreadState::self()->handlePolledCommands();
}

struct wpas_binder_priv *wpas_binder_init(struct wpa_global *global)
{
	struct wpas_binder_priv *priv;
	wpa_supplicant_binder::BinderManager *binder_manager;

	priv = (wpas_binder_priv *)os_zalloc(sizeof(*priv));
	if (!priv)
		return NULL;
	priv->global = global;

	wpa_printf(MSG_DEBUG, "Initing binder control");

	android::ProcessState::self()->setThreadPoolMaxThreadCount(0);
	android::IPCThreadState::self()->disableBackgroundScheduling(true);
	android::IPCThreadState::self()->setupPolling(&priv->binder_fd);
	if (priv->binder_fd < 0)
		goto err;

	wpa_printf(
	    MSG_INFO, "Processing binder events on FD %d", priv->binder_fd);
	/* Look for read events from the binder socket in the eloop. */
	if (eloop_register_read_sock(
		priv->binder_fd, wpas_binder_sock_handler, global, priv) < 0)
		goto err;

	binder_manager = wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		goto err;
	binder_manager->registerBinderService(global);
	/* We may not need to store this binder manager reference in the
	 * global data strucure because we've made it a singleton class. */
	priv->binder_manager = (void *)binder_manager;

	return priv;
err:
	wpas_binder_deinit(priv);
	return NULL;
}

void wpas_binder_deinit(struct wpas_binder_priv *priv)
{
	if (!priv)
		return;

	wpa_printf(MSG_DEBUG, "Deiniting binder control");

	wpa_supplicant_binder::BinderManager::destroyInstance();
	eloop_unregister_read_sock(priv->binder_fd);
	android::IPCThreadState::shutdown();
	os_free(priv);
}

int wpas_binder_register_interface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->binder)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Registering interface to binder control: %s",
	    wpa_s->ifname);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->registerInterface(wpa_s);
}

int wpas_binder_unregister_interface(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->binder)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Deregistering interface from binder control: %s",
	    wpa_s->ifname);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->unregisterInterface(wpa_s);
}

int wpas_binder_register_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !wpa_s->global->binder || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Registering network to binder control: %d", ssid->id);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->registerNetwork(wpa_s, ssid);
}

int wpas_binder_unregister_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	if (!wpa_s || !wpa_s->global->binder || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Deregistering network from binder control: %d",
	    ssid->id);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->unregisterNetwork(wpa_s, ssid);
}

int wpas_binder_notify_state_changed(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->global->binder)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Notifying state change event to binder control: %d",
	    wpa_s->wpa_state);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->notifyStateChange(wpa_s);
}

int wpas_binder_notify_network_request(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
    enum wpa_ctrl_req_type rtype, const char *default_txt)
{
	if (!wpa_s || !wpa_s->global->binder || !ssid)
		return 1;

	wpa_printf(
	    MSG_DEBUG, "Notifying network request to binder control: %d",
	    ssid->id);

	wpa_supplicant_binder::BinderManager *binder_manager =
	    wpa_supplicant_binder::BinderManager::getInstance();
	if (!binder_manager)
		return 1;

	return binder_manager->notifyNetworkRequest(
	    wpa_s, ssid, rtype, default_txt);
}

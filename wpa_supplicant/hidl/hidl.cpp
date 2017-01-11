/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <hwbinder/IPCThreadState.h>

#include <hidl/HidlTransportSupport.h>
#include "hidl_manager.h"

extern "C" {
#include "hidl.h"
#include "hidl_i.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/includes.h"
}

using android::hardware::configureRpcThreadpool;
using android::hardware::IPCThreadState;
using android::hardware::wifi::supplicant::V1_0::implementation::HidlManager;

void wpas_hidl_sock_handler(
    int /* sock */, void * /* eloop_ctx */, void * /* sock_ctx */)
{
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

	configureRpcThreadpool(1, true /* callerWillJoin */);
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

void wpas_hidl_notify_anqp_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *result,
    const struct wpa_bss_anqp *anqp)
{
	if (!wpa_s || !wpa_s->global->hidl || !bssid || !result || !anqp)
		return;

	wpa_printf(
	    MSG_DEBUG,
	    "Notifying ANQP query done to hidl control: " MACSTR "result: %s",
	    MAC2STR(bssid), result);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyAnqpQueryDone(wpa_s, bssid, result, anqp);
}

void wpas_hidl_notify_hs20_icon_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *file_name,
    const u8 *image, u32 image_length)
{
	if (!wpa_s || !wpa_s->global->hidl || !bssid || !file_name || !image)
		return;

	wpa_printf(
	    MSG_DEBUG, "Notifying HS20 icon query done to hidl control: " MACSTR
		       "file_name: %s",
	    MAC2STR(bssid), file_name);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyHs20IconQueryDone(
	    wpa_s, bssid, file_name, image, image_length);
}

void wpas_hidl_notify_hs20_rx_subscription_remediation(
    struct wpa_supplicant *wpa_s, const char *url, u8 osu_method)
{
	if (!wpa_s || !wpa_s->global->hidl || !url)
		return;

	wpa_printf(
	    MSG_DEBUG,
	    "Notifying HS20 subscription remediation rx to hidl control: %s",
	    url);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyHs20RxSubscriptionRemediation(
	    wpa_s, url, osu_method);
}

void wpas_hidl_notify_hs20_rx_deauth_imminent_notice(
    struct wpa_supplicant *wpa_s, u8 code, u16 reauth_delay, const char *url)
{
	if (!wpa_s || !wpa_s->global->hidl || !url)
		return;

	wpa_printf(
	    MSG_DEBUG,
	    "Notifying HS20 deauth imminent notice rx to hidl control: %s",
	    url);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyHs20RxDeauthImminentNotice(
	    wpa_s, code, reauth_delay, url);
}

void wpas_hidl_notify_disconnect_reason(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return;

	wpa_printf(
	    MSG_DEBUG, "Notifying disconnect reason to hidl control: %d",
	    wpa_s->disconnect_reason);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyDisconnectReason(wpa_s);
}

void wpas_hidl_notify_assoc_reject(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return;

	wpa_printf(
	    MSG_DEBUG, "Notifying assoc reject to hidl control: %d",
	    wpa_s->assoc_status_code);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyAssocReject(wpa_s);
}

void wpas_hidl_notify_wps_event_fail(
    struct wpa_supplicant *wpa_s, uint8_t *peer_macaddr, uint16_t config_error,
    uint16_t error_indication)
{
	if (!wpa_s || !peer_macaddr)
		return;

	wpa_printf(
	    MSG_DEBUG, "Notifying Wps event fail to hidl control: %d, %d",
	    config_error, error_indication);

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyWpsEventFail(
	    wpa_s, peer_macaddr, config_error, error_indication);
}

void wpas_hidl_notify_wps_event_success(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return;

	wpa_printf(MSG_DEBUG, "Notifying Wps event success to hidl control");

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyWpsEventSuccess(wpa_s);
}

void wpas_hidl_notify_wps_event_pbc_overlap(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return;

	wpa_printf(
	    MSG_DEBUG, "Notifying Wps event PBC overlap to hidl control");

	HidlManager *hidl_manager = HidlManager::getInstance();
	if (!hidl_manager)
		return;

	hidl_manager->notifyWpsEventPbcOverlap(wpa_s);
}

/*
 * hidl interface for wpa_supplicant daemon
 * Copyright (c) 2004-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2016, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_HIDL_HIDL_H
#define WPA_SUPPLICANT_HIDL_HIDL_H

#ifdef _cplusplus
extern "C" {
#endif  // _cplusplus

/**
 * This is the hidl RPC interface entry point to the wpa_supplicant core.
 * This initializes the hidl driver & HidlManager instance and then forwards
 * all the notifcations from the supplicant core to the HidlManager.
 */
struct wpas_hidl_priv;
struct wpa_global;

struct wpas_hidl_priv *wpas_hidl_init(struct wpa_global *global);
void wpas_hidl_deinit(struct wpas_hidl_priv *priv);

#ifdef CONFIG_CTRL_IFACE_HIDL
int wpas_hidl_register_interface(struct wpa_supplicant *wpa_s);
int wpas_hidl_unregister_interface(struct wpa_supplicant *wpa_s);
int wpas_hidl_register_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
int wpas_hidl_unregister_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
int wpas_hidl_notify_state_changed(struct wpa_supplicant *wpa_s);
int wpas_hidl_notify_network_request(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
    enum wpa_ctrl_req_type rtype, const char *default_txt);
void wpas_hidl_notify_anqp_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *result,
    const struct wpa_bss_anqp *anqp);
void wpas_hidl_notify_hs20_icon_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *file_name,
    const u8 *image, u32 image_length);
void wpas_hidl_notify_hs20_rx_subscription_remediation(
    struct wpa_supplicant *wpa_s, const char *url, u8 osu_method);
void wpas_hidl_notify_hs20_rx_deauth_imminent_notice(
    struct wpa_supplicant *wpa_s, u8 code, u16 reauth_delay, const char *url);
void wpas_hidl_notify_disconnect_reason(struct wpa_supplicant *wpa_s);
void wpas_hidl_notify_assoc_reject(struct wpa_supplicant *wpa_s);
void wpas_hidl_notify_wps_event_fail(
    struct wpa_supplicant *wpa_s, uint8_t *peer_macaddr, uint16_t config_error,
    uint16_t error_indication);
void wpas_hidl_notify_wps_event_success(struct wpa_supplicant *wpa_s);
void wpas_hidl_notify_wps_event_pbc_overlap(struct wpa_supplicant *wpa_s);
#else   // CONFIG_CTRL_IFACE_HIDL
static inline int wpas_hidl_register_interface(struct wpa_supplicant *wpa_s)
{
	return 0;
}
static inline int wpas_hidl_unregister_interface(struct wpa_supplicant *wpa_s)
{
	return 0;
}
static inline int wpas_hidl_register_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	return 0;
}
static inline int wpas_hidl_unregister_network(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	return 0;
}
static inline int wpas_hidl_notify_state_changed(struct wpa_supplicant *wpa_s)
{
	return 0;
}
static inline int wpas_hidl_notify_network_request(
    struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
    enum wpa_ctrl_req_type rtype, const char *default_txt)
{
	return 0;
}
static void wpas_hidl_notify_anqp_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *result,
    const struct wpa_bss_anqp *anqp)
{
}
static void wpas_hidl_notify_hs20_icon_query_done(
    struct wpa_supplicant *wpa_s, const u8 *bssid, const char *file_name,
    const u8 *image, u32 image_length)
{
}
static void wpas_hidl_notify_hs20_rx_subscription_remediation(
    struct wpa_supplicant *wpa_s, const char *url, u8 osu_method)
{
}
static void wpas_hidl_notify_hs20_rx_deauth_imminent_notice(
    struct wpa_supplicant *wpa_s, u8 code, u16 reauth_delay, const char *url)
{
}
static void wpas_hidl_notify_disconnect_reason(struct wpa_supplicant *wpa_s) {}
static void wpas_hidl_notify_assoc_reject(struct wpa_supplicant *wpa_s) {}
static void wpas_hidl_notify_wps_event_fail(
    struct wpa_supplicant *wpa_s, struct wps_event_fail *fail)
{
}
static void wpas_hidl_notify_wps_event_success(struct wpa_supplicant *wpa_s) {}
static void wpas_hidl_notify_wps_event_pbc_overlap(struct wpa_supplicant *wpa_s)
{
}
#endif  // CONFIG_CTRL_IFACE_HIDL

#ifdef _cplusplus
}
#endif  // _cplusplus

#endif  // WPA_SUPPLICANT_HIDL_HIDL_H

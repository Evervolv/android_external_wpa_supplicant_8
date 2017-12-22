/*
 * hidl interface for wpa_hostapd daemon
 * Copyright (c) 2004-2018, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2018, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "hostapd.h"
#include "hidl_return_util.h"

namespace android {
namespace hardware {
namespace wifi {
namespace hostapd {
namespace V1_0 {
namespace implementation {
using hidl_return_util::call;

Hostapd::Hostapd(struct hapd_interfaces* interfaces) : interfaces_(interfaces)
{}

Return<void> Hostapd::addAccessPoint(
    const IfaceParams& iface_params, const NetworkParams& nw_params,
    addAccessPoint_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::addAccessPointInternal, _hidl_cb, iface_params,
	    nw_params);
}

Return<void> Hostapd::removeAccessPoint(
    const hidl_string& iface_name, removeAccessPoint_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::removeAccessPointInternal, _hidl_cb, iface_name);
}

HostapdStatus Hostapd::addAccessPointInternal(
    const IfaceParams& iface_params, const NetworkParams& nw_params)
{
	return {HostapdStatusCode::SUCCESS, ""};
}

HostapdStatus Hostapd::removeAccessPointInternal(const std::string& iface_name)
{
	return {HostapdStatusCode::SUCCESS, ""};
}
}  // namespace implementation
}  // namespace V1_0
}  // namespace hostapd
}  // namespace wifi
}  // namespace hardware
}  // namespace android

#!/bin/sh

# This script will run the dhcp client. If `vlan_id=` in `/proc/cmdline` has a value, it will run the dhcp client only on the
# VLAN interface.
# This script accepts an input parameter of true or false.
# true: run the dhcp client with the one shot option
# false: run the dhcp client as a service
set -x

run_dhcp_client() {
	one_shot="$1"
	al="eth*"

	if grep "vlan_id" /proc/cmdline; then
		al="eth*.*"
	fi

	if [ "$one_shot" = "true" ]; then
		# always return true for the one shot dhcp call so it doesn't block Hook from starting up.
		/sbin/dhcpcd --nobackground -f /dhcpcd.conf --allowinterfaces "${al}" -1 || true
	else
		/sbin/dhcpcd --nobackground -f /dhcpcd.conf --allowinterfaces "${al}"
	fi

}

# we always return true so that a failure here doesn't block the next container service from starting. Ideally, we always
# want the getty service to start so we can debug failures.
run_dhcp_client "$1" || true

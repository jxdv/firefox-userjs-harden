#!/usr/bin/env python3

"""ffhrd is a small stdlib only utility to increase the security of a FireFox profile"""

# Copyright (c) 2024 jxdv
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import platform
import sys
import os

# Sources:
# https://wiki.mozilla.org/Privacy/Privacy_Task_Force/firefox_about_config_privacy_tweeks
FIREFOX_CONFIG_SETTINGS = {
	"Isolate all browser identifier sources (e.g. cookies) to the first party domain, with the goal of preventing tracking across different domains": ("privacy.firstparty.isolate", "true"),
	"Make FireFox more resistant to browser fingerprinting": ("privacy.resistFingerprinting", "true"),
	"Disable offline cache": ("browser.cache.offline.enable", "false"),
	"Stop FireFox from sending any pings when clicking on URLs": ("browser.send_pings", "false"),
	"Disable temporary storing closed tabs (even with history turned off)": ("browser.sessionstore.max_tabs_undo", "0"),
	"Disable preloading of autocomplete URLs": ("browser.urlbar.speculativeConnect.enabled", "false"),
	"Do not reveal to website owners the battery status of your device": ("dom.battery.enabled", "false"),
	"Block websites from getting notifications if you copy / paste / cut something from a web page": ("dom.event.clipboardevents.enabled", "false"),
	"Disable geolocation": ("geo.enabled", "false"),
	"Disable tracking of the status of your microphone and camera": ("media.navigator.enabled", "false"),
	"Block third-party cookies": ("network.cookie.cookieBehavior", "1"),
	"Delete cookies at the end of every session": ("network.cookie.lifetimePolicy", "2"),
	"Send only the scheme, host, and port in the Referer header": ("network.http.referer.trimmingPolicy", "2"),
	"Only send Referer header when the full hostnames match": ("network.http.referer.XOriginPolicy", "2"),
	"When sending Referer across origins, only send scheme, host, and port in the Referer header of cross-origin requests": ("network.http.referer.XOriginTrimmingPolicy", "2"),
	"Disable WebGL": ("webgl.disabled", "true")
}


def get_ff_config_path():
	ff_config_path = None
	sys_platform = platform.system()
	match sys_platform:
		case "Linux":
			ff_config_path = os.path.expanduser("~/snap/firefox/common/.mozilla/firefox")
		case "Windows":
			ff_config_path = "%APPDATA%\\Mozilla\\Firefox\\Profiles\\"
		case "Darwin":
			ff_config_path = ""

	return ff_config_path


def get_ff_profile(ff_config_path):
	subfolders = [f.path for f in os.scandir(ff_config_path) if f.is_dir()]
	print(subfolders)


def harden():
	if not sys.version_info >= (3, 10):
		sys.stderr.write("ffhrd requires at least Python 3.10 to run..")
		sys.exit(1)

	firefox_config_path = get_ff_config_path()
	if not firefox_config_path:
		sys.stderr.write("Failed to find FireFox config directory..")
		sys.exit(1)

	get_ff_profile(firefox_config_path)


if __name__ == "__main__":
	try:
		harden()
	except KeyboardInterrupt:
		print("\nAborting..")
		try:
			sys.exit(130)
		except SystemExit:
			os._exit(130)

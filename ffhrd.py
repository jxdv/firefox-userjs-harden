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
import shutil
import sys
import os

"""
Sources:
https://wiki.mozilla.org/Privacy/Privacy_Task_Force/firefox_about_config_privacy_tweeks
https://github.com/pyllyukko/user.js/blob/master/user.js
https://brainfucksec.github.io/firefox-hardening-guide
https://brainfucksec.github.io/firefox-hardening-guide
---
The key value is there to describe what the setting is for,
It isn't currently used in the script anywhere, but it might
be used in the future
"""
FIREFOX_CONFIG_SETTINGS = {
	"Set startup homepage to blank page": ("browser.startup.page", "1"),
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
	"Disable WebGL": ("webgl.disabled", "true"),
	"Disable service workers": ("dom.serviceWorkers.enabled", "false"),
	"Disable Web notifications": ("dom.webnotifications.enabled", "false"),
	"Disable DOM timing API": ("dom.enable_performance", "false"),
	"Disable resource timing API": ("dom.enable_resource_timing", "false"),
	"Disable Web audio API": ("dom.webaudio.enabled", "false"),
	"Don't log geolocation requests to the console if geolocation is enabled": ("geo.wifi.logging.enabled", "false"),
	"Disable raw TCP sock support": ("dom.mozTCPSocket.enabled", "false"),
	"Disable leaking network / browser connection information via JavaScript": ("dom.netinfo.enabled", "false"),
	"Disable network API": ("dom.network.enabled", "false"),
	"Disable WebRTC": ("media.peerconnection.enabled", "false"),
	"Disable telephony API": ("dom.telephony.enabled", "false"),
	"Disable 'beacon' asynchronous HTTP transfers": ("beacon.enabled", "false"),
	"Disable copy to clipboard functionality via JavaScript": ("dom.allow_cut_copy", "false"),
	"Disable speech recognition": ("media.webspeech.recognition.enable", "false"),
	"Disable speech synthesis": ("media.webspeech.synth.enabled", "false"),
	"Disable sensor API": ("device.sensors.enabled", "false"),
	"Disable gamepad API to prevent USB enumeration": ("dom.gamepad.enabled", "false"),
	"Disable VR devices API": ("dom.vr.enabled", "false"),
	"Disable vibrator API": ("dom.vibrator.enabled", "false"),
	"Disable archive API": ("dom.archivereader.enabled", "false"),
	"Spoof dual-core CPU": ("dom.maxHardwareConcurrency", "2"),
	"Disable WASM": ("javascript.options.wasm", "false"),
	"Disable face detection": ("camera.control.face_detection.enabled", "false"),
	"Set Accept-Language HTTP header to en-US regardless of FireFox localization": ("intl.accept_languages", "en-US, en"),
	"Do not use OS values to determine locale, force using FireFox locale setting": ("intl.locale.matchOS", "false"),
	"Do not use Mozilla-provided location-specific search engines": ("browser.search.geoSpecificDefaults", "false"),
	"Do not automatically send selection to clipboard on some Linux distros": ("clipboard.autocopy", "false"),
	"Prevent leaking application locale / date format using JavaScript": ("javascript.use_us_english_locale", "true"),
	"Do not submit invalid URIs entered in the address bar to the default search engine": ("keyword.enabled", "false"),
	"Do not trim HTTP off of URLs in the address bar": ("browser.urlbar.trimURLs", "false"),
	"Do not try to guess domain names when entering an invalid domain name in the search bar": ("browser.fixup.alternate.enabled", "false"),
	"Strip password from URLs if browser.fixup.alternate.enabled is enabled": ("browser.fixup.hide_user_pass", "true"),
	"Send DNS request through SOCKS when SOCKS proxying is in use": ("network.proxy.socks_remote_dns", "true"),
	"Do not monitor OS online / offline connection state": ("network.manage-offline-status", "false"),
	"Enforce mixed active content blocking": ("security.mixed_content.block_active_content", "true"),
	"Disable JAR from opening unsafe file types": ("network.jar.open-unsafe-types", "false"),
	"Disable scripting of Plugins by JavaScript": ("security.xpconnect.plugin.unrestricted", "false"),
	"Set file URI origin policy": ("security.fileuri.strict_origin_policy", "true"),
	"Disable displaying JavaScript in history URLs": ("browser.urlbar.filter.javascript", "true"),
	"Disable asm.js": ("javascript.options.asmjs", "false"),
	"Disable Scalable Vector Graphics in OpenType fonts": ("gfx.font_rendering.opentype_svg.enabled", "false"),
	"Disable video stats to reduce fingerpriting threat": ("media.video_stats.enabled", "false"),
	"Do not use document specified fonts to prevent installed font enumeration": ("browser.display.use_document_fonts", "0"),
	"Disable pocket extension": ("extensions.pocket.enabled", "false"),
	"Disable screenshots extension": ("extensions.Screenshots.disabled", "true"),
	"Disable PDJFS scripting": ("pdfjs.enableScripting", "false"),
	"Enable containers and show the UI settings": ("privacy.userContext.enabled", "true"),
	"Always get asked where to save files": ("browser.download.useDownloadDir", "false"),
	"Disable adding downloads to system's 'recent documents' list": ("browser.download.manager.addToRecentDocs", "false")
}


class Color:
	RED = "\033[31m"
	GREEN = "\033[32m"
	RESET = "\033[0m"


def print_logo():
	print(r"""
 ______   ______   __  __     ______     _____    
/\  ___\ /\  ___\ /\ \_\ \   /\  == \   /\  __-.  
\ \  __\ \ \  __\ \ \  __ \  \ \  __<   \ \ \/\ \ 
 \ \_\    \ \_\    \ \_\ \_\  \ \_\ \_\  \ \____- 
  \/_/     \/_/     \/_/\/_/   \/_/ /_/   \/____/ 

                                                  
WARNING: Hardening settings may break some site functionalities..
You should carefully go through `FIREFOX_CONFIG_SETTINGS` and comment out settings you don't want to use
	""")


def get_ff_config_path():
	ff_config_path = None
	sys_platform = platform.system()
	match sys_platform:
		case "Linux":
			ff_config_path = os.path.expanduser("~/snap/firefox/common/.mozilla/firefox")
		case "Windows":
			ff_config_path = "%APPDATA%\\Mozilla\\Firefox\\Profiles\\"
		case "Darwin":
			raise NotImplementedError
		case _:
			sys.stderr.write(Color.RED + "[-] Unknown operating system detected!" + Color.RESET)
			sys.exit(1)

	return ff_config_path


def get_ff_profiles(ff_config_path):
	ff_profiles = []
	subfolders = [f.path for f in os.scandir(ff_config_path) if f.is_dir()]

	for folder in subfolders:
		if folder.endswith(".default") or "profile" in folder:
			ff_profiles.append(folder)

	return ff_profiles


def get_harden_settings():
	harden_settings = "// Created by ffhrd - github.com/jxdv/ffhrd\n\n"

	for v in FIREFOX_CONFIG_SETTINGS.values():
		# Deserialize setting value
		opt, val = v

		# Add option to final settings
		harden_settings += f'user_pref("{opt}", {val});\n'

	return harden_settings


def harden_profile(ff_profile):
	user_js_file = "user.js"
	user_js_path = os.path.join(ff_profile, user_js_file)

	# User can either overwrite or create a new user.js file if it already exists
	if os.path.isfile(user_js_path):
		print(f"Found an already existing 'user.js' in '{ff_profile}'")
		choice = input("Would you like to overwrite it or create a new user_temp.js? (overwrite / temp)\nffhrd> ").lower()
		match choice:
			case "overwrite":
				pass
			case "temp":
				user_js_file = "user_temp.js"
			case _:
				print("Wrong choice.")
				return

	harden_settings = get_harden_settings()
	fullpath = os.path.join(ff_profile, user_js_file)
	try:
		with open(fullpath, "w") as f:
			f.write(harden_settings)
	except OSError:
		sys.stderr.write(Color.RED + f"[-] OS Error occurred while writing hardening settings to '{fullpath}'" + Color.RESET)
		sys.exit(1)
	except Exception as e:
		sys.stderr.write(Color.RED + f"[-] Unknown Error occurred while writing hardening settings to '{fullpath}': {e}" + Color.RESET)
		sys.exit(1)
	else:
		print(Color.GREEN + f"[+] '{fullpath}' created" + Color.RESET)


def harden():
	# Need Python >= 3.10 because of match statements
	if not sys.version_info >= (3, 10):
		sys.stderr.write(Color.RED + "[-] ffhrd requires at least Python 3.10 to run..\n" + Color.RESET)
		sys.exit(1)

	firefox_config_path = get_ff_config_path()
	if not firefox_config_path:
		sys.stderr.write(Color.RED + "[-] Failed to find FireFox config directory..\n" + Color.RESET)
		sys.exit(1)

	ff_profiles = get_ff_profiles(firefox_config_path)
	if not ff_profiles:
		sys.stderr.write(Color.RED + "[-] Failed to find any FireFox profiles..\n" + Color.RESET)
		sys.exit(1)

	# Make the user choose which FireFox profile is going to be hardened if there's > 1
	if len(ff_profiles) > 1:
		print("-" * 80)
		print(Color.GREEN + "[+] Multiple FireFox profiles found:" + Color.RESET)
		for i in range(len(ff_profiles)):
			print(f"{i} - {ff_profiles[i]}")
		print("-" * 80)

		try:
			profile_choice = int(input(f"Choose a profile to harden: (0..{len(ff_profiles) - 1})\nffhrd> "))
		except ValueError:
			sys.stderr.write(Color.RED + "[-] Incorrect input..\n" + Color.RESET)
			sys.exit(1)
		else:
			if profile_choice not in range(0, len(ff_profiles)):
				print("Wrong choice.")
				return

			profile = ff_profiles[profile_choice]

	# Create a backup of the chosen FireFox profile
	profile_name = profile.split("/")[-1]
	backup_dir = os.path.join(os.path.expanduser("~"), "ffhrd", f"{profile_name}-backup")
	shutil.copytree(profile, backup_dir, dirs_exist_ok=True, symlinks=True)
	print(Color.GREEN + f"[+] Backup created at '{backup_dir}'" + Color.RESET)

	# Harden the FireFox profile
	harden_profile(profile)


if __name__ == "__main__":
	print_logo()
	try:
		harden()
	except KeyboardInterrupt:
		print("\nAborting..")
		try:
			sys.exit(130)
		except SystemExit:
			os._exit(130)

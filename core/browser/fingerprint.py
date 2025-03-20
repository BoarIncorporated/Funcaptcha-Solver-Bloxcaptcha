from base64 import b64encode
from random import choice, randint
from json import dumps
from mmh3 import hash128
from hashlib import md5
from time import time
from uuid import uuid4
from typing import Dict, List, Union, Any

from core.mouse_movement.biometrics import Biometrics

__all__ = ("Fingerprint",)


class Fingerprint:
    def __init__(
        self,
        ip_info: Dict[str, Union[str, int, List[str]]],
        challenge_info: Dict[str, Union[bool, str]],
        browser_info: Dict[str, str],
        bda_fingerprint: Dict[str, Union[str, int, List[int]]],
    ) -> None:
        self.challenge_info = challenge_info
        #sec_ch_ua: str = browser_info["Sec-Ch-Ua"]
        #sec_ch_ua_split: List[str] = sec_ch_ua.split('"')
        #self.data_brands: str = ",".join(
        #    [sec_ch_ua_split[1], sec_ch_ua_split[5], sec_ch_ua_split[9]]
        #)
        self.language: str = ip_info["language"]
        self.languages: List[str] = ip_info["languages"]
        self.timezone_offset: int = ip_info["timezone_offset"]
        self.bda_fingerprint = bda_fingerprint
        self.media_devices: List[Union[List[str], str]] = self._generate_media_devices()
        self.speech_voice: str = self._select_speech_voice()

    def _generate_md5_hash(self, input_string: str) -> str:
        return md5(input_string.encode("utf-8")).hexdigest()

    def _generate_x64_hash(self, input_string: str, seed: int) -> str:
        hashed_value: int = hash128(input_string, seed)
        return str(
            hex(((hashed_value & 0xFFFFFFFFFFFFFFFF) << 64) + (hashed_value >> 64))
        ).removeprefix("0x")

    def _format_extended_string(self, input_string: str) -> str:
        return dumps(input_string)[1:-1].replace('\\"', '"').replace("\\\\", "\\")

    def _format_numeric_value(self, value: Union[float, int]) -> Union[float, int]:
        numeric_string: str = str(value)
        if "." in numeric_string:
            decimal_part: str = numeric_string.split(".")[1]
            if len(decimal_part) == 2 and decimal_part[1] == "0":
                return float(numeric_string[:-1])
            if decimal_part == "0":
                return int(numeric_string[:-2])
        return value

    def _compute_webgl_hash(self, fingerprint_data: Dict[str, str]) -> str:
        webgl_data: Dict[str, str] = {
            key: value
            for key, value in fingerprint_data.items()
            if key.startswith("webgl_")
        }
        return self._generate_x64_hash(
            ",".join([item for pair in webgl_data.items() for item in pair]), 0
        )

    def _select_speech_voice(self) -> str:
        speech_voices: List[str] = [
            "Google US English || en-US",
            "Google UK English Female || en-GB",
            "Google UK English Male || en-GB",
            "Google español || es-ES",
            "Google español de Estados Unidos || es-US",
            "Google français || fr-FR",
            "Google हिन्दी || hi-IN",
            "Google Bahasa Indonesia || id-ID",
            "Google italiano || it-IT",
            "Google 日本語 || ja-JP",
            "Google 한국의 || ko-KR",
            "Google Nederlands || nl-NL",
            "Google polski || pl-PL",
            "Google português do Brasil || pt-BR",
            "Google русский || ru-RU",
            "Google 普通话（中国大陆） || zh-CN",
            "Google 粤語（香港） || zh-HK",
            "Google 國語（臺灣） || zh-TW",
            "Microsoft Mark - English (United States) || en-US",
            "Microsoft Zira - English (United States) || en-US",
            "Microsoft Hazel - English (United Kingdom) || en-GB",
            "Microsoft Susan - English (United Kingdom) || en-GB",
        ]
        return choice(speech_voices)

    def _generate_media_devices(self) -> List[Union[List[str], str]]:
        device_types: List[str] = [
            "audioinput",
            "audiooutput",
            "videoinput",
            "videooutput",
        ]
        selected_device_types: List[str] = []
        device_info: List[Dict[str, str]] = []

        for _ in range(randint(1, 3)):
            selected_type: str = choice(device_types)
            device_types.remove(selected_type)

            selected_device_types.append(selected_type)
            device_info.append({"kind": selected_type, "id": "", "group": ""})

        devices_json: str = dumps(device_info, separators=(",", ":"))
        devices_hash: str = self._generate_md5_hash(devices_json)

        return [selected_device_types, devices_hash]

    def generate_fingerprint_data(self) -> Dict[str, Union[str, int, bool, List[str]]]:
        js_fonts: str = (
            "Arial,Arial Black,Arial Narrow,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,"
            "Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,"
            "Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,"
            "Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,"
            "Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings"
        )

        fingerprint_data: Dict[str, Union[str, int, bool, List[str]]] = {
            "DNT": "unknown",
            "L": self.language,
            "D": self.bda_fingerprint["colorDepth"],
            "PR": self.bda_fingerprint["pixelRatio"],
            "S": ",".join(map(str, self.bda_fingerprint["screen"])),
            "AS": ",".join(map(str, self.bda_fingerprint["availScreen"])),
            "TO": self.timezone_offset,
            "SS": True,
            "LS": True,
            "IDB": True,
            "B": False,
            "ODB": False,
            "CPUC": "unknown",
            "PK": self.bda_fingerprint["platform"],
            "CFP": self.bda_fingerprint["cfp"],
            "FR": False,
            "FOS": False,
            "FB": False,
            "JSF": js_fonts if self.challenge_info["jsf_enabled"] else "",
            "P": (
                "Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,"
                "WebKit built-in PDF"
            ),
            "T": ",".join(map(str, [0, False, False])),
            "H": self.bda_fingerprint["hardwareConcurrency"],
            "SWF": False,
        }

        return fingerprint_data

    def get_enhanced_fingerprint(self) -> Dict[str, Any]:
        enhanced_fp: Dict[str, Any] = {
            "webgl_extensions": self.bda_fingerprint["webglExtensions"],
            "webgl_extensions_hash": self._generate_x64_hash(
                self.bda_fingerprint["webglExtensions"], 0
            ),
            "webgl_renderer": self.bda_fingerprint["webglRenderer"],
            "webgl_vendor": self.bda_fingerprint["webglVendor"],
            "webgl_version": self.bda_fingerprint["webglVersion"],
            "webgl_shading_language_version": self.bda_fingerprint[
                "webglShadingLanguageVersion"
            ],
            "webgl_aliased_line_width_range": self.bda_fingerprint[
                "webglAliasedLineWidthRange"
            ],
            "webgl_aliased_point_size_range": self.bda_fingerprint[
                "webglAliasedPointSizeRange"
            ],
            "webgl_antialiasing": self.bda_fingerprint["webglAntialiasing"],
            "webgl_bits": "8,8,24,8,8,0",
            "webgl_max_params": self.bda_fingerprint["webglMaxParams"],
            "webgl_max_viewport_dims": self.bda_fingerprint["webglMaxViewportDims"],
            "webgl_unmasked_vendor": self.bda_fingerprint["webglUnmaskedVendor"],
            "webgl_unmasked_renderer": self.bda_fingerprint["webglUnmaskedRenderer"],
            "webgl_vsf_params": self.bda_fingerprint["webglVsfParams"],
            "webgl_vsi_params": self.bda_fingerprint["webglVsiParams"],
            "webgl_fsf_params": self.bda_fingerprint["webglFsfParams"],
            "webgl_fsi_params": self.bda_fingerprint["webglFsiParams"],
            "webgl_hash_webgl": "",
            "user_agent_data_brands": None,#"Not A(Brand,Chromium,Google Chrome",#self.data_brands,
            "user_agent_data_mobile": False,
            "navigator_connection_downlink": self._format_numeric_value(
                (randint(10, 100) * 5) / 100
            ),
            "navigator_connection_downlink_max": None,
            "network_info_rtt": randint(1, 20) * 50,
            "network_info_save_data": False,
            "network_info_rtt_type": None,
            "screen_pixel_depth": self.bda_fingerprint["colorDepth"],
            "navigator_device_memory": 8,
            "navigator_pdf_viewer_enabled": True,
            "navigator_languages": self.languages,
            "window_inner_width": 0,
            "window_inner_height": 0,
            "window_outer_width": self.bda_fingerprint["availScreen"][0],
            "window_outer_height": self.bda_fingerprint["availScreen"][1],
            "browser_detection_firefox": False,
            "browser_detection_brave": False,
            "browser_api_checks": [
                "permission_status: true",
                "eye_dropper: true",
                "audio_data: true",
                "writable_stream: true",
                "css_style_rule: true",
                "navigator_ua: true",
                "barcode_detector: false",
                "display_names: true",
                "contacts_manager: false",
                "svg_discard_element: false",
                "usb: defined",
                "media_device: defined",
                "playback_quality: true",
            ],
            "browser_object_checks": "554838a8451ac36cb977e719e9d6623c",
            "29s83ih9": "68934a3e9455fa72420237eb05902327⁣",
            "audio_codecs": self.bda_fingerprint["audioCodecs"],
            "audio_codecs_extended_hash": self._generate_md5_hash(
                self.bda_fingerprint["audioCodecsExtended"]
            ),
            "video_codecs": self.bda_fingerprint["videoCodecs"],
            "video_codecs_extended_hash": self._generate_md5_hash(
                self.bda_fingerprint["videoCodecsExtended"]
            ),
            "media_query_dark_mode": False,
            "css_media_queries": self.bda_fingerprint["cssMediaQueries"],
            "css_color_gamut": self.bda_fingerprint["cssColorGamut"],
            "css_contrast": self.bda_fingerprint["cssContrast"],
            "css_monochrome": self.bda_fingerprint["cssMonochrome"],
            "css_pointer": self.bda_fingerprint["cssPointer"],
            "css_grid_support": self.bda_fingerprint["cssGridSupport"],
            "headless_browser_phantom": False,
            "headless_browser_selenium": False,
            "headless_browser_nightmare_js": False,
            "headless_browser_generic": 4,
            "1l2l5234ar2": f"{int(time())}⁣",
            "document__referrer": self.challenge_info["website_url"],
            "window__ancestor_origins": self.challenge_info["ancestor_origins"],
            "window__tree_index": self.challenge_info["tree_index"],
            "window__tree_structure": self.challenge_info["tree_structure"],
            "window__location_href": f'{self.challenge_info["service_url"]}/v2/2.11.6/enforcement.f9e933a9f186f0bdb8e44dd39534e940.html',
            "client_config__sitedata_location_href": self.challenge_info[
                "location_h_ref"
            ],
            "client_config__language": (
                self.language.lower()
                if self.challenge_info["language_enabled"]
                else None
            ),
            "client_config__surl": self.challenge_info["service_url"],
            "c8480e29a": f'{self._generate_md5_hash(self.challenge_info["service_url"])}⁢',
            "client_config__triggered_inline": False,
            "mobile_sdk__is_sdk": False,
            "audio_fingerprint": "124.04347527516074",
            "navigator_battery_charging": True,
            "media_device_kinds": self.media_devices[0],
            "media_devices_hash": self.media_devices[1],
            "navigator_permissions_hash": "67419471976a14a1430378465782c62d",
            "math_fingerprint": "3b2ff195f341257a6a2abbc122f4ae67",
            "supported_math_functions": "e9dd4fafb44ee489f48f7c93d0f48163",
            "screen_orientation": "landscape-primary",
            "rtc_peer_connection": 5,
            "4b4b269e68": str(uuid4()),
            "6a62b2a558": "f9e933a9f186f0bdb8e44dd39534e940",
            "is_keyless": False,
            "speech_default_voice": self.speech_voice,
            "speech_voices_hash": self._generate_md5_hash(self.speech_voice),
            "4ca87df3d1": "Ow==", #b64encode(
            #    Biometrics().retrieve_mouse_bio().encode()
            #).decode(),
            "867e25e5d4": "Ow==",
            "d4a306884c": "Ow==",
        }

        enhanced_fp["webgl_hash_webgl"] = self._compute_webgl_hash(enhanced_fp)
        return enhanced_fp
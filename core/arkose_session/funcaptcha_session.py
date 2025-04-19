from curl_cffi import requests
from time import time
from random import random, randint, choice, gauss
import httpx
from json import dumps
from base64 import b64encode
from urllib.parse import unquote
from funcaptcha.core.obfuscation.crypto import encrypt_data
from funcaptcha.core.browser.arkose_bda import ArkoseBDA
from funcaptcha.core.obfuscation.dapib import DapibBreaker
from funcaptcha.core.mouse_movement.biometrics import Biometrics
from funcaptcha.core.utilities.ip_intelligence import IpIntelligence
from funcaptcha.core.obfuscation.proof_of_work import ProofOfWork
from typing import Dict, List, Any, Optional, Tuple

__all__ = ("FunCaptchaSolver",)

class FunCaptchaSolver:
    def __init__(self,
                challenge_information: Dict[str, str], 
                browser_information: Dict[str, str],
                arkose_fingerprint: Dict[str, str],
                proxy: str) -> None:
        self.http_session = requests.Session(
            impersonate="chrome116",
            default_headers=0,
            akamai="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
            extra_fp={
                "tls_signature_algorithms": [
                    "ecdsa_secp256r1_sha256",
                    "rsa_pss_rsae_sha256",
                    "rsa_pkcs1_sha256",
                    "ecdsa_secp384r1_sha384",
                    "rsa_pss_rsae_sha384",
                    "rsa_pkcs1_sha384",
                    "rsa_pss_rsae_sha512",
                    "rsa_pkcs1_sha512"
                ],
                "tls_grease": True,
                "tls_permute_extensions": True
            },
            verify=False
        )
        self.proxy = proxy
        self.http_session.proxies = {
            "https": self.proxy
        }
        self.arkose_fingerprint: Dict[str, str] = arkose_fingerprint
        
        self.ip_information: IpIntelligence = IpIntelligence(self.http_session).fetch_ip_data()
        self.challenge_information: Dict[str, str] = challenge_information
        self.browser_information: Dict[str, str] = browser_information
        self.proof_of_work_enabled: bool = None
        
        self.session_cookie = self.browser_information["Cookie"]
        
        if self.session_cookie != "":
            self.session_cookie += "; "
            
        self.user_agent: str = self.browser_information["User-Agent"]
        self.sec_platform: str = '"Windows"' if 'Windows NT' in self.user_agent else '"macOs"'
        
        self.ip_language: str = self.ip_information["language"]
        self.accept_language: str = self.ip_information["accept_language"]
        
        self._get_cloudfare_cookie()
        
        x, y = int(gauss(150, 20)), int(gauss(150, 20))
        self.screen_clicks = dumps({"sc": [max(0, x), max(0, y)]}) 
        
        self.answer_history: List[str, str] = []
        self.tguess_history: List[str, str] = []
        
        self.tguess_called: int = 0
            
    def _encode_data(self, input_data: str) -> str:
        result: List[str] = []
        for char in input_data:
            if ord(char) > 127 or char in " %$&+,/:;=?@<>%{}":
                result.append(f'%{ord(char):02X}')
            else:
                result.append(char)
        return ''.join(result)
    
    def _url_encode(self, params: Dict[str, str]) -> str:
        encoded_params: str = ''
        for idx, (key, value) in enumerate(params.items()):
            encoded_params += (
                f'{key}={self._encode_data(value)}&' if idx != len(params) - 1 else f'{key}={self._encode_data(value)}'
            )
        return encoded_params
    
    def _sort_headers(self, input_headers: Dict[str, str]) -> Dict[str, str]:
        key_order: list[str] = [
            "Host",
            "Cookie",
            "Content-Length",
            "sec-ch-ua-platform",
            "Cache-Control",
            "x-ark-esync-value",
            "Accept-Language",
            #"sec-ch-ua",
            "sec-ch-ua-mobile",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "X-NewRelic-Timestamp",
            "X-Requested-ID",
            "X-Requested-With",
            "Accept",
            "Content-Type",
            "Origin",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Referer",
            "Accept-Encoding",
            "Connection",
            "Priority"
        ]
        order_index: Dict[str, int] = {
            header: i for i, header in enumerate(key_order)
        }

        def sort_key(header_pair: Tuple[str, str]) -> int:
            header_name, _ = header_pair
            return order_index.get(header_name, len(key_order))

        sorted_headers: Dict[str, str] = dict(
            sorted(input_headers.items(), key=sort_key)
        )

        return sorted_headers
    
    def _generate_newrelic_timestamp(self) -> str:
        timestamp_ms: int = int(time() * 1000)
        timestamp_str: str = str(timestamp_ms)
        return f"{timestamp_str[:7]}00{timestamp_str[7:13]}"
    
    def _set_biometrics(self) -> None:
        biometrics_data: str = '{"mbio":"%s","tbio":"","kbio":""}' % Biometrics().retrieve_mouse_bio()
        self.biometrics: str = b64encode(biometrics_data.encode("utf-8")).decode("utf-8")
        
    def _get_cloudfare_cookie(self) -> None:
        self.http_session.headers = self._sort_headers({
            "Cookie": self.session_cookie,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": self.accept_language,
            "Referer": self.challenge_information["website_url"],
            #"sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.sec_platform,
            "Sec-Fetch-Dest": "script",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self.user_agent,
        })

        response: Any = self.http_session.get(
            f"{self.challenge_information['service_url']}/v2/{self.challenge_information['public_key']}/api.js"
        )

        self.cloudfare_cookie: str = f"_cfuvid={response.cookies.get('_cfuvid').split(';')[0]}"
        
    def _parse_token(self, token: str) -> Dict[str, str]:
        return {
            unquote(key): unquote(value)
            for key, value in (pair.split("=") for pair in token.split("|"))
        }
        
    def _get_funcaptcha_token(self) -> None:
        current_time: int = int(time())
        rounded_time: str = str(current_time - (current_time % 21600))

        random_value: str = str(random())

        bda_generator = ArkoseBDA(self.ip_information, self.challenge_information, self.browser_information, self.arkose_fingerprint)
        encrypted_bda: str = bda_generator.generate_bda()

        site_value: str = self.challenge_information["website_url"].rstrip("/")

        payload: Dict[str, Any] = {
            "bda": b64encode(encrypted_bda.encode("utf-8")).decode("utf-8"),
            "public_key": self.challenge_information["public_key"],
            "site": site_value,
            "userbrowser": self.user_agent,
            "capi_version": "2.11.6",
            "capi_mode": self.challenge_information["capi_mode"],
            "style_theme": self.challenge_information["style_theme"],
            "rnd": random_value,
        }

        if self.challenge_information["language_enabled"]:
            payload["language"] = self.ip_language.lower()

        if "extra_data" in self.challenge_information:
            for key, value in self.challenge_information["extra_data"].items():
                payload[f"data[{key}]"] = value

        self.http_session.headers = self._sort_headers({
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.accept_language,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": "",
            "Origin": self.challenge_information["service_url"],
            "Referer": f"{self.challenge_information['service_url']}/v2/2.11.6/enforcement.f9e933a9f186f0bdb8e44dd39534e940.html",
            #"sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.user_agent,
            "x-ark-esync-value": rounded_time,
            "Priority": "u=1, i"
        })

        self.http_session.cookies.clear()
        self.http_session.headers["Cookie"] = f"{self.session_cookie}{self.cloudfare_cookie}; timestamp={self._generate_newrelic_timestamp()}"

        response = self.http_session.post(
            f"{self.challenge_information['service_url']}/fc/gt2/public_key/{self.challenge_information['public_key']}",
            data=self._url_encode(payload),
        )

        try:
            response_data: Dict[str, Any] = response.json()
            self.funcaptcha_token: str = response_data["token"]
            self.proof_of_work_enabled: bool = response_data["pow"]
        except Exception:
            self.funcaptcha_token = None
            
    def _send_analytics(self, analytics: Dict[str, Any], add_request_id: bool) -> None:
        self.http_session.headers = self._sort_headers({
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.accept_language,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": "",
            "Origin": self.challenge_information["service_url"],
            "Referer": self.embed_url,
            #"sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.user_agent,
            "X-NewRelic-Timestamp": self._generate_newrelic_timestamp(),
            "X-Requested-With": "XMLHttpRequest",
        })

        self.http_session.cookies.clear()
        self.http_session.headers["Cookie"] = f"{self.session_cookie}{self.cloudfare_cookie}; timestamp={self.http_session.headers['X-NewRelic-Timestamp']}"

        if add_request_id:
            self.http_session.headers["X-Requested-ID"] = encrypt_data(self.screen_clicks, f"REQUESTED{self.session_token}ID", False)
            self.http_session.headers = self._sort_headers(self.http_session.headers)

        self.http_session.post(
            f"{self.challenge_information['service_url']}/fc/a/",
            data=self._url_encode(analytics),
        )
        
    def _get_challenge(self) -> None:
        self._initialize_challenge_details()
        self._set_embed_url()
        self._set_initial_headers()
        self._clear_cookies()
        self._set_cookie_header()

        embed_url_no_queries, params = self._extract_url_and_params()
        self.http_session.get(embed_url_no_queries, params=params)

        if self.proof_of_work_enabled:
            self._process_proof_of_work()

        self._initialize_challenge()
        self._process_game_data()
        self._send_initial_analytics()

        proof_of_work = ProofOfWork().solve_analytics_pow()
        analytics = self._prepare_analytics_data("begin app", "user clicked verify", proof_of_work)
        self._send_analytics(analytics, True)

    def _initialize_challenge_details(self) -> None:
        self.analytics_tier = self.funcaptcha_token.split("at=")[1].split("|")[0]
        self.session_id = self.funcaptcha_token.split("|")[1].split("r=")[1].split("|")[0]

    def _set_embed_url(self) -> None:
        token_info = self._parse_token(f"session={self.funcaptcha_token}")
        self.embed_url = (
            f"{self.challenge_information['service_url']}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?"
            f"{self._url_encode(token_info)}&theme={self._encode_data(self.challenge_information['style_theme'])}"
        )

    def _set_initial_headers(self) -> None:
        self.http_session.headers = self._sort_headers({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
                      "application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.accept_language,
            "Cookie": "",
            "Referer": f"{self.challenge_information['service_url']}/v2/2.11.6/enforcement.f9e933a9f186f0bdb8e44dd39534e940.html",
            #"sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.sec_platform,
            "Sec-Fetch-Dest": "iframe",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.user_agent,
        })

    def _clear_cookies(self) -> None:
        self.http_session.cookies.clear()

    def _set_cookie_header(self) -> None:
        self.http_session.headers["Cookie"] = (
            f"{self.session_cookie}{self.cloudfare_cookie}; timestamp={self._generate_newrelic_timestamp()}"
        )

    def _extract_url_and_params(self) -> Tuple[str, Dict[str, str]]:
        embed_url_no_queries = self.embed_url.split("?")[0]
        queries = self.embed_url.split("?")[1]
        params = {}

        if "&" not in queries:
            params[queries.split("=")[0]] = queries.split("=")[1]
        else:
            for query in queries.split("&"):
                key, value = query.split("=")
                params[key] = value

        return embed_url_no_queries, params

    def _process_proof_of_work(self) -> None:
        pow_class = ProofOfWork()
        pow_response = self.http_session.get(
            f"{self.challenge_information['service_url']}/pows/setup?session_token={self.funcaptcha_token.split('|')[0]}"
        )
        self.http_session.get(pow_response.json()["url"])
        pow_data = pow_class.solve_proof_of_work(
            pow_response.json()["seed"],
            pow_response.json()["leading_zero_count"],
            self.funcaptcha_token.split("|")[0],
            pow_response.json()["pow_token"],
        )
        self.http_session.post(
                f"{self.challenge_information['service_url']}/pows/check", json=pow_data
            ).json()

    def _initialize_challenge(self) -> None:
        self.http_session.get(
            f"{self.challenge_information['service_url']}/fc/init-load/?session_token={self.funcaptcha_token.split('|')[0]}"
        )
        self.funcaptcha_token_info = self._parse_token(f"token={self.funcaptcha_token}")

    def _process_game_data(self) -> None:
        response = self.http_session.post(
            f"{self.challenge_information['service_url']}/fc/gfct/",
            data=self._prepare_challenge_data(),
        ).json()
        self._extract_game_data(response)

    def _prepare_challenge_data(self) -> Dict[str, Any]:
        return {
            "token": self.funcaptcha_token_info["token"],
            "sid": self.session_id,
            "render_type": "canvas",
            "lang": self.ip_information["language"].lower()
            if self.challenge_information["language_enabled"]
            else "",
            "isAudioGame": False,
            "is_compatibility_mode": False,
            "apiBreakerVersion": "green",
            "analytics_tier": str(self.analytics_tier),
        }

    def _extract_game_data(self, response: Dict[str, Any]) -> None:
        self.game_data = response["game_data"]
        self.game_type = self.game_data["gameType"]
        self.session_token = response["session_token"]
        self.challenge_id = response["challengeID"]
        self.challenge_url = response["challengeURL"]
        self.dapib_url = response.get("dapib_url", None)
        if self.game_type == 4:
            self.variant = self.game_data.get(
                "variant", response["game_data"]["instruction_string"]
            )
        elif self.game_type == 3:
            self.variant = self.game_data["game_variant"]
        self.waves = self.game_data["waves"]
        self.challenge_imgs = self.game_data["customGUI"]["_challenge_imgs"]

    def _send_initial_analytics(self) -> None:
        self._send_analytics(
            self._prepare_analytics_data(
                "Site URL",
                f"{self.challenge_information['service_url']}/v2/2.11.6/enforcement.f9e933a9f186f0bdb8e44dd39534e940.html",
            ),
            False,
        )
        self._send_analytics(
            self._prepare_analytics_data("loaded", "game loaded"), False
        )

    def _prepare_analytics_data(
        self, category: str, action: str, additional_data: Dict[str, Any] = {}
    ) -> Dict[str, Any]:
        data = {
            "sid": self.session_id,
            "session_token": self.session_token,
            "analytics_tier": str(self.analytics_tier),
            "disableCookies": "false",
            "render_type": "canvas",
            "is_compatibility_mode": "false",
            "category": category,
            "action": action,
        }
        data.update(additional_data)
        return data
    
    def _get_base64_image(self, index: int) -> bytes:
        headers: Dict[str, str] = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd", 
            "Accept-Language": self.accept_language,
            "Cookie": f'{self.session_cookie}{self.cloudfare_cookie}; timestamp={self._generate_newrelic_timestamp()}',
            "Priority": "u=1, i",
            "Referer": self.embed_url,
            #"Sec-Ch-Ua": self.sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": self.sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors", 
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.user_agent
        }
        self.http_session.headers = self._sort_headers(headers)
        self.http_session.cookies.clear()

        url, query_string = self.challenge_imgs[index].split("?", 1)
        query_params: Dict[str, str] = dict(
            param.split("=") for param in query_string.split("&")
        )
        
        response = self.http_session.get(url=self.challenge_imgs[index])

        return b64encode(response.content)

    def _submit_tile_answer(self, tile_index: int) -> Dict[str, Any]:
        tile_index += 1

        if tile_index > 3:
            x_coord: int = ((tile_index - 3) * 100) - randint(2, 98)
            y_coord: int = randint(102, 200)
        else:
            x_coord: int = (tile_index * 100) - randint(2, 98)
            y_coord: int = randint(1, 98)
        
        px_value: str = str((x_coord // 3) / 100)
        py_value: str = str((y_coord // 2) / 100)

        self.answer_history.append({"px": px_value, "py": py_value, "x": x_coord, "y": y_coord})

        encrypted_guess: str = encrypt_data(
            dumps(self.answer_history).replace(" ", ""), 
            self.session_token, 
            False
        )
        requested_id: str = encrypt_data(
            self.screen_clicks, 
            f"REQUESTED{self.session_token}ID", 
            False
        )

        headers: Dict[str, str] = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.accept_language,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": "",
            "Origin": self.challenge_information["service_url"],
            "Referer": self.embed_url,
            #"sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.user_agent,
            "X-NewRelic-Timestamp": self._generate_newrelic_timestamp(),
            "X-Requested-ID": requested_id,
            "X-Requested-With": "XMLHttpRequest",
        }

        headers["Cookie"] = (
            f'{self.session_cookie}{self.cloudfare_cookie}; timestamp={headers["X-NewRelic-Timestamp"]}'
        )
        self.http_session.headers = self._sort_headers(headers)
        self.http_session.cookies.clear()

        payload: Dict[str, str] = {
            "session_token": self.session_token,
            "game_token": self.challenge_id,
            "sid": self.session_id,
            "guess": encrypted_guess,
            "render_type": "canvas",
            "analytics_tier": str(self.analytics_tier),
            "bio": self.biometrics,
            "is_compatibility_mode": "false",
        }

        return self.http_session.post(
            f'{self.challenge_information["service_url"]}/fc/ca/',
            data=self._url_encode(payload)
        ).json()
        
    def _submit_index_answer(self, selected_index: int) -> Dict[str, Any]:
        headers: Dict[str, str] = {"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br, zstd",
                                   "Accept-Language": self.accept_language,
                                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                                   "Cookie": f'{self.session_cookie}{self.cloudfare_cookie}; timestamp={self._generate_newrelic_timestamp()}',
                                   "Origin": self.challenge_information["service_url"], "Referer": self.embed_url,
                                   #"sec-ch-ua": self.sec_ch_ua, 
                                   "sec-ch-ua-mobile": "?0",
                                   "sec-ch-ua-platform": self.sec_platform, "Sec-Fetch-Dest": "empty",
                                   "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
                                   "User-Agent": self.user_agent}

        self.http_session.headers = self._sort_headers(headers)
        self.http_session.cookies.clear()

        token_parts: List[str] = self.session_token.split(".")
        token_first_part, token_second_part = token_parts[0], token_parts[1]

        self.answer_history.append({"index": selected_index})
        self.tguess_history.append({"index": str(selected_index), token_first_part: token_second_part})

        dapib_transformed_guess: Optional[str] = None
        if self.dapib_url is not None:
            dapib_solver = DapibBreaker(self.http_session, self.dapib_url, self.challenge_information["service_url"])
            dapib_transformed_guess = dapib_solver.fetch_transformed_guess(self.tguess_history, self.tguess_called)
            self.tguess_called += 1

        encrypted_guess: str = encrypt_data(
            dumps(self.answer_history).replace(" ", ""), 
            self.session_token, 
            False
        )
        encrypted_tguess: str = (
            encrypt_data(dumps(self.tguess_history).replace(" ", ""), self.session_token, False)
            if dapib_transformed_guess is None
            else encrypt_data(dapib_transformed_guess, self.session_token, False)
        )
        requested_id: str = encrypt_data(
            self.screen_clicks, 
            f"REQUESTED{self.session_token}ID", 
            False
        )

        headers.update({
            "X-NewRelic-Timestamp": self._generate_newrelic_timestamp(),
            "X-Requested-ID": requested_id,
            "X-Requested-With": "XMLHttpRequest",
        })

        headers["Cookie"] = f'{self.session_cookie}{self.cloudfare_cookie}; timestamp={headers["X-NewRelic-Timestamp"]}'
        self.http_session.headers = self._sort_headers(headers)
        self.http_session.cookies.clear()

        payload: Dict[str, str] = {
            "session_token": self.session_token,
            "game_token": self.challenge_id,
            "sid": self.session_id,
            "guess": encrypted_guess,
            "render_type": "canvas",
            "analytics_tier": str(self.analytics_tier),
            "bio": self.biometrics,
            "is_compatibility_mode": "false",
            "tguess": encrypted_tguess,
        }

        return self.http_session.post(
            f'{self.challenge_information["service_url"]}/fc/ca/',
            data=self._url_encode(payload)
        ).json()

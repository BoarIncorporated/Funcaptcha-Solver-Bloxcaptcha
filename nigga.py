from typing import Any, Dict
from curl_cffi import requests
import re

def solve_funcaptcha(proxy_url: str) -> str | None:
    session: requests.Session = requests.Session()
    challengeInfo: Dict[str, Any] = {
        "public_key": "85800716-F435-4981-864C-8B90602D10F7",
        "website_url": "https://www.match.com",
        "service_url": "https://match-api.arkoselabs.com",
        "capi_mode": "lightbox",
        "style_theme": "default",
        "language_enabled": False,
        "jsf_enabled": True,
        #"extra_data": {"blob": blob_data},
        "ancestor_origins": ["https://www.match.com"],
        "tree_index": [5],
        "tree_structure": "[[[]],[],[],[[]],[],[],[],[],[],[],[]]",
        "location_h_ref": "https://www.match.com/login",
    }

    browserInfo: Dict[str, str] = {
        "Cookie": "",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    }

    payload: dict[str, Any] = {
        "api_key": "BLOXCAPTCHA-ADMIN-6FBNYL1CO61RT6897G0LRMS33BIHUCG5",
        "challenge_info": challengeInfo,
        "browser_info": browserInfo,
        "proxy": "http://25740687-res_US_sppj4m2fmer:ocfgtron@gw.cloudbypass.com:1288",#proxy_url,
    }

    solution: Dict = session.post(
        "http://127.0.0.1:5000/solve/FunCaptcha", json=payload, timeout=600
    ).json()
    print(solution)
    if "solution" in solution:
        return solution.get("solution", None)
    

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
URL_LOGIN = "https://mobi.match.com/login"
URL_API = "https://mobi.match.com/api"

headers = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

response = requests.get(URL_LOGIN, headers=headers, proxies={"https": "http://25740687-res_US_sppj4m2fmer:ocfgtron@gw.cloudbypass.com:1288"})
csrf_token = re.search(r'"_csrf":"(.*?)"', response.text).group(1)

solution = solve_funcaptcha("http://127.0.0.1:5000/solve/FunCaptcha")

data = {
    "requests": {
        "g0": {
            "resource": "auth",
            "operation": "create",
            "params": "login",
            "body": {
                "email": "tgrube79@gmail.com",
                "password": "pumpkin44",
                "rememberMe": True,
                "submitted": False,
                "recaptchaResponse": f"a:{solution}",
                "reactivateUrl": "reactivateAccount"
            }
        }
    },
    "context": {
        "locale": "en-US",
        "_csrf": csrf_token
    }
}

headers.update({
    "Content-Type": "application/json",
    "accept": "*/*",
    "x-requested-with": "XMLHttpRequest",
    "adrum": "isAjax:true",
    "Referer": URL_LOGIN
})

# Make the login request
response = requests.post(f"{URL_API}?_csrf={csrf_token}&locale=en-US", json=data, headers=headers, proxies={"https": "http://25740687-res_US_sppj4m2fmer:ocfgtron@gw.cloudbypass.com:1288"})

print(response)
print(response.text)
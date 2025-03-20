import pytz
from curl_cffi.requests import Session
from datetime import datetime, timezone
from typing import Dict

__all__ = ("IpIntelligence",)

class IpIntelligence:
    def __init__(self, session: Session) -> None:
        self.http_session: Session = session

    def fetch_ip_data(self) -> Dict[str, str | int]:
        response_ip_address: Dict[str, str] = self.http_session.get(
            "https://wtfismyip.com/json"
        )
        response_json: Dict[str, str] = self.http_session.get(
            "https://api.ipfind.com/",
            headers={
                "origin": "https://ipfind.com",
                "referer": "https://ipfind.com/",
            },
            params={"ip": response_ip_address.json()["YourFuckingIPAddress"]},
        ).json()
        time_zone: Dict[str, str] = response_json["timezone"]
        timezone_offset: int = self.calculate_timezone_offset(time_zone)

        language_code: str = response_json["languages"][0]
        main_language: str = (
            f"{language_code}-{language_code.upper()}"
            if len(language_code) == 2
            else language_code
        )

        language_list: str = ",".join([main_language, main_language.split("-")[0]])

        accept_language: str = self.build_accept_language(language_list)
        
        data = {
            "timezone_offset": timezone_offset,
            "language": main_language,
            "languages": language_list,
            "accept_language": accept_language,
        }
        return data

    def calculate_timezone_offset(self, timezone_str: str) -> int:
        utc_now = datetime.now(timezone.utc)
        local_now = utc_now.astimezone(pytz.timezone(timezone_str))

        utf_offset = local_now.utcoffset()
        if not utf_offset:
            return 0

        return int((utf_offset.total_seconds() / 60) * -1)

    def build_accept_language(self, languages: str) -> str:
        language_list: list[str] = languages.split(",")
        result: list[str] = []

        for i, lang in enumerate(language_list):
            if i == 0:
                result.append(lang)
            else:
                q_value: float = 1.0 - (i * 0.1)
                result.append(f"{lang};q={q_value:.1f}")

        return ",".join(result)


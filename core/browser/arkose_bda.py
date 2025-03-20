from time import time
from random import randint, choice
from re import sub
from json import dumps
from base64 import b64encode
from mmh3 import hash128
from core.obfuscation.crypto import encrypt_data
from core.browser.fingerprint import Fingerprint
from typing import Union, Dict, List

__all__ = ["ArkoseBDA"]


class ArkoseBDA:
    def __init__(
        self,
        ip_info: Dict[str, str],
        challenge_info: Dict[str, str],
        browser_info: Dict[str, str],
        fingerprint_data: Dict[str, str],
    ) -> None:
        self.user_agent: str = browser_info["User-Agent"]
        self.fingerprint: Fingerprint = Fingerprint(
            ip_info, challenge_info, browser_info, fingerprint_data
        )
        self.fingerprint_entries: List[str] = self._prepare_fingerprint_entries(
            self.fingerprint.generate_fingerprint_data()
        )
        self.formatted_fingerprint: str = self._prepare_fingerprint(
            self.fingerprint.generate_fingerprint_data()
        )
        self.enhanced_fp: List[Dict[str, str]] = self._prepare_enhanced_fp(
            self.fingerprint.get_enhanced_fingerprint()
        )
        self.ife_hash_input: str = self._json_stringify(
            dumps(self.fingerprint_entries)[1:-1]
        )

    def _x64hash128(self, data: str, seed: int) -> str:
        hashed_value: int = hash128(data, seed)
        return str(
            hex(((hashed_value & 0xFFFFFFFFFFFFFFFF) << 64) + (hashed_value >> 64))
        ).removeprefix("0x")

    def _json_stringify(self, values: Union[str, List[str]]) -> Union[str, List[str]]:
        if isinstance(values, str):
            return (
                values.replace("None", "null")
                .replace("True", "true")
                .replace("False", "false")
                .replace('"', "")
            )
        return [
            value.replace("None", "null")
            .replace("True", "true")
            .replace("False", "false")
            .replace('"', "")
            for value in values
        ]

    def _format_bda(self, bda: str) -> str:
        bda = sub(
            r'\{"key":"window__tree_index","value":\[(\d+,\s*\d+)\]\}',
            lambda match: sub(r"\s", "", match.group(0)),
            bda,
        )
        bda = sub(
            r"(\"key\":\"navigator_connection_downlink\",\"value\":)\"(\d+\.?\d*)\"",
            lambda match: f"{match.group(1)}{match.group(2)}",
            bda,
        )
        return bda.replace("\\\\", "\\").replace("\\u2062", "⁢").replace("\\u2063", "⁣")

    def _prepare_fingerprint(self, fingerprint: Dict[str, Union[str, int]]) -> str:
        return ";".join(str(value) for value in fingerprint.values())

    def _prepare_fingerprint_entries(
        self, fingerprint: Dict[str, Union[str, int]]
    ) -> List[str]:
        return [f"{key}:{value}" for key, value in fingerprint.items()]

    def _prepare_enhanced_fp(self, enhanced_fp: Dict[str, str]) -> List[Dict[str, str]]:
        return [{"key": key, "value": value} for key, value in enhanced_fp.items()]

    def generate_bda(self) -> str:
        current_time: int = int(time())
        rounded_time: str = str(current_time - (current_time % 21600))
        base64_encoded_time: str = b64encode(str(current_time).encode("utf-8")).decode(
            "utf-8"
        )
        history_length: str = str(randint(1, 8))

        bda: List[Dict[str, Union[str, List[Dict[str, str]]]]] = [
            {"key": "api_type", "value": "js"},
            {"key": "f", "value": self._x64hash128(self.formatted_fingerprint, 0)},
            {"key": "n", "value": base64_encoded_time},
            {
                "key": "wh",
                "value": f"{''.join(choice('0123456789abcdef') for _ in range(32))}|72627afbfd19a741c7da1732218301ac",
            },
            {"key": "enhanced_fp", "value": self.enhanced_fp},
            {"key": "fe", "value": self.fingerprint_entries},
            {"key": "ife_hash", "value": self._x64hash128(self.ife_hash_input, 38)},
            {
                "key": "jsbd",
                "value": '{"HL":'
                + history_length
                + ',"NCE":true,"DT":"","NWD":"false","DMTO":1,"DOTO":1}',
            },
        ]

        formatted_bda: str = self._format_bda(dumps(bda, separators=(",", ":")))
        encryption_key: str = self.user_agent + rounded_time
        return encrypt_data(formatted_bda, encryption_key, True)
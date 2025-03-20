from typing import Dict, Optional
from core.arkose_session.funcaptcha_session import FunCaptchaSolver
from core.image.image_classification import ImageClassification
from core.utilities.output import Console
import concurrent.futures
from time import sleep

OUTPUT = Console()

__all__ = "FunCaptchaTask"


class FunCaptchaTask:
    def __init__(
        self,
        challenge_info: Dict[str, str],
        browser_info: Dict[str, str],
        bda_fingerprint: Dict[str, str],
        proxy: Optional[str] = None,
    ) -> None:
        self.proxy = proxy if proxy != "" else None
        self.interactor = FunCaptchaSolver(
            challenge_info, browser_info, bda_fingerprint, self.proxy
        )

    def _classify_image(self, wave_index: int, old_headers: Dict[str, str]) -> int:
        self.interactor.http_session.headers = old_headers
        img = self.interactor._get_base64_image(wave_index)
        return ImageClassification().classify_image(img, self.interactor.variant)

    def _solve_challenge(self) -> Dict[str, bool]:
        self.interactor._get_cloudfare_cookie()
        self.interactor._get_funcaptcha_token()
        if not self.interactor.funcaptcha_token:
            raise ValueError(
                "Failed to generate FunCaptcha Token, Fingerprint/Blob related issue."
            )

        if "sup=1" in self.interactor.funcaptcha_token:
            OUTPUT._print_success(
                self.interactor.funcaptcha_token.split("|")[0], 0, 4, "suppressed"
            )
            return {"success": True, "solution": self.interactor.funcaptcha_token}

        self.interactor._get_challenge()

        OUTPUT._print_challenge(
            self.interactor.session_token,
            self.interactor.waves,
            self.interactor.game_type,
            self.interactor.variant
        )
        
        old_headers = self.interactor.http_session.headers.copy()
        correct_indices = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(
                    self._classify_image, wave_index, old_headers
                ): wave_index
                for wave_index in range(self.interactor.waves)
            }

            results = {}
            for future in concurrent.futures.as_completed(futures):
                
                wave_index = futures[future]
                results[wave_index] = future.result()

            correct_indices = [results[wave_index] for wave_index in sorted(results)]
        for correct_index in correct_indices:
            self.interactor._set_biometrics()

            if self.interactor.game_type == 4:
                answer_response = self.interactor._submit_index_answer(correct_index)
            else:
                answer_response = self.interactor._submit_tile_answer(correct_index)

            solved = answer_response["solved"]

            if solved:
                OUTPUT._print_success(
                    self.interactor.session_token,
                    self.interactor.waves,
                    self.interactor.game_type,
                    self.interactor.variant
                )
                return {"success": True, "solution": self.interactor.funcaptcha_token}

        OUTPUT._print_failed(
            self.interactor.session_token,
            self.interactor.waves,
            self.interactor.game_type,
            self.interactor.variant
        )
        return {"success": False, "solution": "Failed to solve the captcha."}
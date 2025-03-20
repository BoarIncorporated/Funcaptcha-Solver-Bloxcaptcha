from datetime import datetime
from threading import Lock
from typing import Final


LOCK: Final[Lock] = Lock()


class Console:
    def __init__(self) -> None:
        pass

    def _print_success(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mBloxCAPTCHA\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[92mSolved\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )

    def _print_failed(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mBloxCAPTCHA\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[91mFailed\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )

    def _print_challenge(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mBloxCAPTCHA\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[38;2;255;165;0mChallenge\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )

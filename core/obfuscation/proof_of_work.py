from hashlib import sha512, sha256
from time import time
from random import choices, randint
from string import ascii_lowercase, digits
from decimal import Decimal
from typing import Final, Dict, Any

__all__ = ("ProofOfWork",)


class ProofOfWork:
    def __init__(self) -> None:
        self.START_TIME: Final[float] = time() - randint(20000, 50000)

    def generate_sha256_hash(self, input_data: str) -> str:
        return sha256(input_data.encode()).hexdigest()

    def generate_analytics_pow(self) -> Dict[str, Any]:
        return {
            "challenge": "".join(choices(ascii_lowercase + digits, k=9)),
            "difficulty": 2,
            "timeout": 2,
        }

    def solve_analytics_pow(self) -> Dict[str, Any]:
        state_tracker: Dict[str, Any] = {
            "tryEntries": [{"tryLoc": "root", "completion": {"type": "normal"}}],
            "prev": 0,
            "next": 0,
            "done": False,
            "delegate": None,
            "method": "next",
        }
        pow_data = self.generate_analytics_pow()

        challenge_str: str = pow_data["challenge"]
        difficulty: int = pow_data["difficulty"]
        timeout: int = pow_data["timeout"]

        attempt_count: int = 0
        start_offset: float = None
        expiration_time: float = None
        random_suffix: str = None
        hash_result: str = None
        exec_time: float = None
        time_spent: float = None
        average_time_per_attempt: float = None

        while True:
            state_tracker["prev"] = state_tracker["next"]
            if state_tracker["prev"] == 0:
                attempt_count = 0
                start_offset = time() - self.START_TIME
                expiration_time = start_offset + timeout
            if state_tracker["next"] == 3 or state_tracker["prev"] == 0:
                random_suffix = "".join(choices(ascii_lowercase + digits, k=15))
                state_tracker["next"] = 7
                state_tracker["sent"] = self.generate_sha256_hash(
                    challenge_str + random_suffix
                )
            if state_tracker["next"] == 7:
                hash_result = state_tracker["sent"]
                attempt_count += 1
                if not hash_result.startswith("0" * difficulty):
                    state_tracker["next"] = 14
                else:
                    exec_time = time() - self.START_TIME
                    time_spent = exec_time - start_offset
                    average_time_per_attempt = time_spent / attempt_count
                    return {
                        "cs_": challenge_str,
                        "ct_": str(attempt_count),
                        "g_": random_suffix,
                        "h_": hash_result,
                        "pt_": str(Decimal(time_spent)),
                        "aht_": str(Decimal(average_time_per_attempt)),
                    }
            if state_tracker["next"] == 14:
                state_tracker["next"] = 16
            if state_tracker["next"] == 16:
                state_tracker["next"] = 3

    def solve_proof_of_work(
        self, pow_seed: str, leading_zero_count: int, session_token: str, pow_token: str
    ) -> Dict[str, Any]:
        interaction_count: int = 0
        initial_time: int = randint(2000, 4000)

        while True:
            interaction_count += 1
            random_suffix: str = "".join(choices(ascii_lowercase + digits, k=15))
            hash_result: str = sha512((pow_seed + random_suffix).encode()).hexdigest()
            if hash_result[:leading_zero_count] == "0" * leading_zero_count:
                execution_time: int = initial_time - randint(1000, 1500)
                return {
                    "session_token": session_token,
                    "pow_token": pow_token,
                    "result": random_suffix,
                    "execution_time": round(execution_time),
                    "iteration_count": interaction_count,
                    "hash_rate": interaction_count / execution_time,
                }

from flask import Flask, request, jsonify
from core.arkose_session.arkose_handler import FunCaptchaTask
from time import time
from json import load
from random import shuffle
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from logging import NullHandler, getLogger
import os
import json
import string
import secrets
import warnings

warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    module=r"curl_cffi\.requests\.session"
)


app = Flask(__name__)
logger = getLogger("werkzeug")
logger.addHandler(NullHandler())

fingerprint_files: list[str] = [
    file
    for file in os.listdir("fingerprints")
    if os.path.isfile(os.path.join("fingerprints", file))
]
shuffle(fingerprint_files)

fingerprints: list[str] = fingerprint_files
lock: Lock = Lock()
last_updated: float = time()
fingerprint_index: int = 0
executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=1000)
deduction_amount: float = 0.0009

with open("resources/keys.json", "r") as key_file:
    keys_data: list[dict[str, float | str]] = json.load(key_file)


def save_keys() -> None:
    with open("resources/keys.json", "w") as key_file:
        json.dump(keys_data, key_file, indent=4)


@app.route("/check_balance", methods=["POST"])
def check_balance() -> tuple:
    data: dict = request.get_json()

    if "key" in data:
        for key_info in keys_data:
            if key_info["key"] == data["key"]:
                return jsonify({"Balance": f"${key_info['balance']}"}), 200
        return jsonify({"response": "Invalid key."}), 400
    return jsonify({"response": "Invalid key."}), 400


@app.route("/admin", methods=["POST"])
def admin() -> tuple:
    data: dict = request.get_json()

    if (
        "admin_key" in data
        and "action" in data
        and data["admin_key"] == "NOVAK-Ssh3OOXK5pldXmOHobhh3UZnaAE9p3q"
    ):
        action: str = data["action"]
        key: str | None = data.get("key")
        balance: float | None = data.get("balance")

        if action == "gen_key" and balance is not None:

            def generate_secure_string(length: int = 32) -> str:
                alphabet: str = string.ascii_uppercase + string.digits
                return "".join(secrets.choice(alphabet) for _ in range(length))

            generated_key: str = "BLOXCAPTCHA-" + generate_secure_string()

            keys_data.append({"key": generated_key, "balance": balance})
            save_keys()
            return (
                jsonify(
                    {"response": "Key generated successfully.", "key": generated_key}
                ),
                200,
            )

        if action == "add_key" and key and balance is not None:
            keys_data.append({"key": key, "balance": balance})
            save_keys()
            return jsonify({"response": "Key added successfully.", "key": key}), 200

        if action == "remove_key" and key:
            for key_info in keys_data:
                if key_info["key"] == key:
                    keys_data.remove(key_info)
                    save_keys()
                    return jsonify({"response": "Key removed successfully."}), 200
            return jsonify({"response": "Key not found."}), 404

        if action == "set_balance" and key and balance is not None:
            for key_info in keys_data:
                if key_info["key"] == key:
                    key_info["balance"] = balance
                    save_keys()
                    return jsonify({"response": "Balance set successfully."}), 200
            return jsonify({"response": "Key not found."}), 404

        if action == "increase_balance" and key and balance is not None:
            for key_info in keys_data:
                if key_info["key"] == key:
                    key_info["balance"] += balance
                    save_keys()
                    return jsonify({"response": "Balance increased successfully."}), 200
            return jsonify({"response": "Key not found."}), 404

        if action == "decrease_balance" and key and balance is not None:
            for key_info in keys_data:
                if key_info["key"] == key:
                    if key_info["balance"] >= balance:
                        key_info["balance"] -= balance
                        save_keys()
                        return (
                            jsonify({"response": "Balance decreased successfully."}),
                            200,
                        )
                    return (
                        jsonify({"response": "Insufficient balance to decrease."}),
                        400,
                    )
            return jsonify({"response": "Key not found."}), 404

        return jsonify({"response": "Invalid action or parameters."}), 400
    return jsonify({"response": "Invalid admin key or missing parameters."}), 400


def process_captcha(payload: dict) -> tuple[dict, int]:
    global fingerprint_index, last_updated

    try:
        fingerprint_path: str = fingerprints[fingerprint_index % len(fingerprints)]
        with open(
            os.path.join("fingerprints", fingerprint_path), "r", encoding="utf-8"
        ) as file:
            fingerprint_data: dict = load(file)

        captcha_solver = FunCaptchaTask(
            payload["challenge_info"],
            payload["browser_info"],
            fingerprint_data,
            payload.get("proxy", ""),
        )

        start_time: float = time()
        captcha_solution: str = captcha_solver._solve_challenge().get("solution", "")
        elapsed_time: float = round(time() - start_time, 2)

        if "sup=1" in captcha_solution:
            return {
                "solution": captcha_solution,
                "game_info": {
                    "variant": "silent_pass",
                    "waves": 0,
                    "game_type": 4,
                    "solve_time": elapsed_time,
                },
            }, 200

        interactor = captcha_solver.interactor
        variant: str = interactor.variant
        waves: int = interactor.waves
        game_type: int = interactor.game_type

        if "rid" not in interactor.funcaptcha_token:
            with lock:
                if time() > last_updated:
                    fingerprint_index += 1
                    last_updated = time()
                    
        if captcha_solution == "Failed to solve the captcha.":
            return {"error": "Failed to solve the captcha."}, 500

        return {
            "solution": captcha_solution,
            "game_info": {
                "variant": variant,
                "waves": waves,
                "game_type": game_type,
                "solve_time": elapsed_time,
            },
        }, 200

    except ValueError as error:
        return {"error": str(error)}, 500
    except Exception as error:
        return {"error": f"Unknown / proxy error. {str(error)}"}, 500


@app.route("/solve/FunCaptcha", methods=["POST"])
def fun_captcha_handler() -> tuple:
    payload: dict = request.get_json()

    if "api_key" in payload:
        for key_info in keys_data:
            if key_info["key"] == payload["api_key"]:
                if key_info["balance"] > 0:
                    key_info["balance"] -= deduction_amount
                    save_keys()

                    required_challenge_keys: list[str] = [
                        "public_key",
                        "website_url",
                        "service_url",
                        "capi_mode",
                        "style_theme",
                        "language_enabled",
                        "jsf_enabled",
                        "ancestor_origins",
                        "tree_index",
                        "tree_structure",
                        "location_h_ref",
                    ]
                    required_browser_keys: list[str] = ["User-Agent"]

                    if not all(
                        key in payload.get("challenge_info", {})
                        for key in required_challenge_keys
                    ):
                        return (
                            jsonify(
                                {"error": "Missing required challenge_info parameters."}
                            ),
                            400,
                        )

                    if not all(
                        key in payload.get("browser_info", {})
                        for key in required_browser_keys
                    ):
                        return (
                            jsonify(
                                {"error": "Missing required browser_info parameters."}
                            ),
                            400,
                        )

                    future = executor.submit(process_captcha, payload)
                    result, status_code = future.result()
                    if "error" in result:
                        key_info["balance"] += deduction_amount
                        save_keys()

    return jsonify(result), status_code


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    app.run(host="0.0.0.0", port=5000, threaded=True)
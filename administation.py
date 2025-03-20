import requests
import os

action = input("Enter admin action: ")
admin_key = "NOVAK-Ssh3OOXK5pldXmOHobhh3UZnaAE9p3q"


def admin_actions() -> None:
    if str(action) == "add_key":
        key_string: str = input("Enter key string: ")
        balance_amount: int = input("Enter balance amount: ")
        data: dict = {
            "admin_key": admin_key,
            "action": str(action),
            "key": key_string,
            "balance": balance_amount,
        }
    elif str(action) == "gen_key":
        balance_amount: int = input("Enter balance amount: ")
        data: dict = {
            "admin_key": admin_key,
            "action": str(action),
            "balance": int(balance_amount),
        }

    elif str(action) == "remove_key":
        key_string: str = input("Enter key string: ")
        data: dict = {"admin_key": admin_key, "action": str(action), "key": key_string}
    elif str(action) == "set_balance":
        key_string: str = input("Enter key string: ")
        balance_amount: int = input("Enter balance amount: ")
        data: dict = {
            "admin_key": admin_key,
            "action": str(action),
            "key": key_string,
            "balance": balance_amount,
        }

    elif str(action) == "increase_balance":
        key_string: str = input("Enter key string: ")
        balance_amount: int = input("Enter balance amount: ")
        data: dict = {
            "admin_key": admin_key,
            "action": str(action),
            "key": key_string,
            "balance": balance_amount,
        }

    elif str(action) == "decrease_balance":
        key_string: str = input("Enter key string: ")
        balance_amount: int = input("Enter balance amount: ")
        data: dict = {
            "admin_key": admin_key,
            "action": str(action),
            "key": key_string,
            "balance": balance_amount,
        }

    response = requests.post("http://127.0.0.1:5000/admin", json=data)

    print(f"Response Code: {response.status_code} | JSON: {response.json()}")


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    admin_actions()

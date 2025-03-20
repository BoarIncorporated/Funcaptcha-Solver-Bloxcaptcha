from curl_cffi.requests import Session
from re import search, sub
from subprocess import run, PIPE
from typing import List, Dict

__all__ = ("DapibBreaker",)


class DapibBreaker:
    def __init__(self, session: Session, base_url: str, secure_url: str) -> None:
        self.http_session: Session = session
        self.base_url: str = base_url
        self.secure_url: str = secure_url

    def fetch_transformed_guess(self, answer_list: List[str], call_count: int) -> str:
        pattern = r'([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})/(\d+)'
        match = search(pattern, self.base_url)

        uuid = match.group(1)
        number = match.group(2)

        if call_count == 0:
            self.http_session.headers["Origin"] = self.secure_url
            self.http_session.get(f"{self.secure_url}/params/sri/dapib/{uuid}/{number}")

        self.http_session.headers["Sec-Fetch-Dest"] = "script"
        js_code = self.http_session.get(self.base_url).text
        self.http_session.headers["Sec-Fetch-Dest"] = "empty"

        js_code = js_code.replace("(function(){const ", "function main(){const ")
        pattern = r'function\s+(\w+)\(answers\)'
        match = search(pattern, js_code)
        function_name = match.group(1)
        js_code = sub(r'try{.+', '{try{console.log(JSON.stringify(' + function_name + '(' + str(answer_list) + ')));}catch(e){}}};main();', js_code)

        result = run(["node", "-e", js_code], stdout=PIPE).stdout.decode("utf-8").strip("\n")
        return result

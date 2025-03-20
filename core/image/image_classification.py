import time
import random

from curl_cffi.requests import Session
from typing import Dict, List, Tuple, Optional

__all__ = ["ImageClassification"]


class ImageClassification:
    def __init__(self) -> None:
        self.xevil_nodes: List[Tuple[str, str]] = [
            ("http://193.233.254.2:80", "bd205a35d544e2981ff852820af2a723"),
        ]
        self.api_url_create: str = "/in.php"
        self.api_url_get: str = "/res.php"
        self.request_session: Session = Session()
        self.request_session.timeout = 10

    def classify_image(self, image_data: bytes, task_description: str) -> Optional[int]:
        print(image_data[:32])
        shuffled_nodes = self.xevil_nodes[:]
        random.shuffle(shuffled_nodes)
        for api_url, api_key in shuffled_nodes:
            payload: Dict[str, str] = {
                "key": api_key,
                "recaptcha": "1",
                "method": "base64",
                "body": image_data.decode(),
                "imginstructions": task_description,
            }

            try:
                response = self.request_session.post(
                    f"{api_url}{self.api_url_create}", data=payload
                )
                
                response_content: str = response.text
                if not response_content.startswith("OK"):
                    continue

                task_id: str = response_content.split("|")[1]
                status_payload: Dict[str, str] = {
                    "key": api_key,
                    "action": "get",
                    "id": task_id,
                }
                while True:
                    solution_response = self.request_session.post(
                        f"{api_url}{self.api_url_get}", data=status_payload
                    )
                    solution_content = solution_response.text
                    
                    if solution_content.startswith("OK"):
                        result = int(solution_content.split("|")[1]) - 1
                        return result
            
                    elif solution_content == "ERROR_CAPTCHA_UNSOLVABLE":
                        break

                    time.sleep(1)

            except Exception:
                return self.classify_image(image_data, task_description)

        return None

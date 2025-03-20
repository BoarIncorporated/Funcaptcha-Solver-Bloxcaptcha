from random import randint, choice, random
from typing import List, Optional

__all__ = ("Biometrics",)


class Biometrics:
    def __init__(self) -> None:
        self.mouse_bio: str = ""
        self.last_movement: Optional[List[int]] = None
        self.current_x: int = 0
        self.current_y: int = 0
        self.current_time: int = 0
        self.movement_count: int = 0

        self.initialize_starting_point()
        self.generate_mouse_bio()

    def initialize_starting_point(self) -> None:
        self.current_time = randint(1000, 3000)
        self.current_x, self.current_y = randint(100, 300), randint(100, 300)

        movement: List[int] = [self.current_time, 0, self.current_x, self.current_y]
        self.last_movement = movement

        self.mouse_bio += f"{self.current_time},0,{self.current_x},{self.current_y};"
        self.movement_count += 1

    def generate_mouse_bio(self) -> None:
        max_movements: int = randint(10, 149)
        movement_index: int = 0

        increase_x: bool = choice([True, False])
        increase_y: bool = choice([True, False])

        direction_steps_x: int = randint(1, 3) if random() <= 0.7 else randint(4, 15)
        direction_steps_y: int = randint(1, 3) if random() <= 0.7 else randint(4, 15)

        while movement_index < max_movements:
            self.current_time += randint(10, 60)

            if direction_steps_x == 0:
                direction_steps_x = randint(1, 5)
                increase_x = choice([True, False])

            if direction_steps_y == 0:
                direction_steps_y = randint(1, 5)
                increase_y = choice([True, False])

            if not increase_x and self.current_x - 10 > 0:
                self.current_x -= randint(1, 3) if random() <= 0.7 else randint(4, 15)
            elif increase_x and self.current_x + 10 < 500:
                self.current_x += randint(1, 3) if random() <= 0.7 else randint(4, 15)

            if not increase_y and self.current_y - 10 > 0:
                self.current_y -= randint(1, 3) if random() <= 0.7 else randint(4, 15)
            elif increase_y and self.current_y + 10 < 500:
                self.current_y += randint(1, 3) if random() <= 0.7 else randint(4, 15)

            movements_remaining: int = max_movements - movement_index

            if movements_remaining == 2:
                self.mouse_bio += (
                    f"{self.current_time},1,{self.current_x},{self.current_y};"
                )
            elif movements_remaining == 1:
                self.mouse_bio += (
                    f"{self.current_time},2,{self.current_x},{self.current_y};"
                )
            else:
                self.mouse_bio += (
                    f"{self.current_time},0,{self.current_x},{self.current_y};"
                )

            direction_steps_x -= 1
            direction_steps_y -= 1

            movement_index += 1

    def retrieve_mouse_bio(self) -> str:
        return self.mouse_bio

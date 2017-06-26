import re
import os.path
from typing import List
from .utils import color


def test_file(file_name: str) -> bool:
    res = os.path.isfile(file_name)
    if not res:
        print(color(f"{{red}}*** File {file_name} doesnt exist ***{{endc}}"))
    return bool(res)


def test_number(number: str) -> bool:
    pattern = re.compile("0[xX][0-9a-fA-F]+|\d+")
    res = pattern.match(number)
    if not res:
        print(color(f"{{red}}*** Number {number} not valid ***{{endc}}"))
    return bool(res)


def test_bytes(args: List[str]) -> bool:
    res = True
    pattern = re.compile("0[xX][0-9a-fA-F]{1,2}")
    for b in args:
        res = res and pattern.match(b)
        if not res:
            print(color(f"{{red}}*** Byte {b} not valid ***{{endc}}"))
    return res

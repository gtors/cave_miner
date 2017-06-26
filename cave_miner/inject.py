from contextlib import ExitStack
from .utils import *


def inject(payload_name: str, file_name: str, straddr: str) -> None:
    print(color("{yellow}[*]{bold} Starting injection into binary...{endc}")

    addr = parse_int(straddr)

    with ExitStack() as stack:
        payload = stack.enter_context(open(payload_name, "rb")).read()
        victim = stack.enter_context(open(file_name, "rb")).read()

        buf = victim[:addr] + payload + victim[addr + len(payload):]
        stack.enter_context(open(f"{file_name}.mod", "w")).write(buf)

    print(color("{yellow}[*]{bold} Injection finished.{endc}")

# Copyright (c) 2021-2021 Zkrypto Inc.

import time
import functools


def print_wrapper(num):
    def wrapper(func):
        @functools.wraps(func)
        def decorator(*args, **kwargs):
            start_time = time.time()
            msg = f"[INFO - {num}] :: START , Call :    {func.__name__:37s}  Time : [ {0:03f} s]"
            print_msg_box(msg, title=func.__name__)
            res = func(*args, **kwargs)
            msg = f"[INFO - {num}] :: END   , Call :    {func.__name__:37s}  Time : [ {round(time.time() - start_time, 4):3f} s]"
            print_msg_box(msg, title=func.__name__)
            return res
        return decorator
    return wrapper


def print_msg_box(msg, indent=15, width=None, title=None):
    """Print message-box with optional title."""
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'  # upper_border
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'  # title
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'  # underscore
    box += ''.join([f'║{space}{line:<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'  # lower_border
    print(box)


def print_value(value, indent=15, name=None, func_name=None):
    value = value if isinstance(value, str) else str(value)
    print(
        f"\n{' '*5} [INFO] func name : {func_name:^20s} | meaning : {name:>10s} ] :: [ {value[:10]:>20s} ]{' '*5}\n")

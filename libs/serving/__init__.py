import json

"""
Package for generating locally dependent server responses (server quotes)
"""

default_localization = "en-gb"
cashed_strings = {}


def refresh() -> None:
    global cashed_strings
    with open(f"libs/serving/strings/{default_localization}.json", encoding="utf-8") as f:
        cashed_strings = json.load(f)


def response_quote(key: str) -> str:
    return cashed_strings[key]


def set_localization(locality) -> None:
    global default_localization
    default_localization = locality
    refresh()

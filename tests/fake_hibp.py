"""A small, fixed copy of HIBP's public breach list, so tests never touch the network."""
import json
from unittest import mock

import breaches


def breach(domain, when, passwords=True, **extra):
    b = {"Name": domain.split(".")[0].title(), "Title": domain.split(".")[0].title(),
         "Domain": domain, "BreachDate": when, "AddedDate": f"{when}T00:00:00Z",
         "DataClasses": ["Email addresses"] + (["Passwords"] if passwords else []),
         "IsVerified": True, "IsFabricated": False, "IsSpamList": False, "IsRetired": False}
    b.update(extra)
    return b


DEFAULT = [breach("spotify.com", "2020-11-23"),
           breach("steam.com", "2021-05-01", passwords=False),   # no passwords: ignored
           breach("example-fake.com", "2022-01-01", IsFabricated=True)]


def patch(items=None, calls=None):
    """mock.patch for breaches.http_get serving `items` (DEFAULT if None)."""
    def get(url):
        if calls is not None:
            calls.append(url)
        return json.dumps(DEFAULT if items is None else items).encode()
    return mock.patch.object(breaches, "http_get", get)

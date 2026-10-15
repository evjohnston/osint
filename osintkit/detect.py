"""Guess what kind of target the user passed in."""

import ipaddress
import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")

TYPES = ("email", "domain", "ip", "url", "phone", "username")


def detect(target):
    t = target.strip()
    if t.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(t):
        return "email"
    if PHONE_RE.match(t) and sum(c.isdigit() for c in t) >= 7:
        return "phone"
    if DOMAIN_RE.match(t):
        return "domain"
    return "username"

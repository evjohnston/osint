"""Phone number intelligence. Uses Google's libphonenumber port if installed."""

import os
import re

from ..net import get_json, q
from ..runner import Skip, run_checks


def parse(number):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
    except ImportError:
        raise Skip("pip install phonenumbers  (offline carrier/region/line-type lookup)")
    n = phonenumbers.parse(number, None if number.startswith("+") else os.environ.get("OSINT_DEFAULT_REGION", "US"))
    types = {v: k for k, v in vars(phonenumbers.PhoneNumberType).items() if k.isupper()}
    return {
        "valid": phonenumbers.is_valid_number(n),
        "possible": phonenumbers.is_possible_number(n),
        "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country_code": n.country_code,
        "region": phonenumbers.region_code_for_number(n),
        "location": geocoder.description_for_number(n, "en"),
        "original_carrier": carrier.name_for_number(n, "en") or None,
        "line_type": types.get(phonenumbers.number_type(n)),
        "timezones": list(timezone.time_zones_for_number(n)),
    }


def numverify(number):
    key = os.environ.get("NUMVERIFY_API_KEY")
    if not key:
        raise Skip("set NUMVERIFY_API_KEY")
    _, j = get_json(f"http://apilayer.net/api/validate?access_key={key}&number={q(re.sub(r'[^0-9+]', '', number))}")
    return j


def investigate(number, progress=None):
    results = run_checks({"libphonenumber": parse, "Numverify": numverify}, number.strip(), on_done=progress)
    p = results["libphonenumber"].get("data") or {}
    summary = {k: p.get(k) for k in ("valid", "e164", "location", "original_carrier", "line_type")} if p else \
        {"digits": re.sub(r"\D", "", number)}
    return {"summary": summary, "sources": results}

import re
from typing import Literal
import sys
import os
import git


sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

# FUTURE VALIDATION IDEA
# From VirusTotal artifact research
#
# JA3 should be same as md5
# JA3S should be same as md5
# JARM 62 alphanumeric characters. Mix of hash and fuzzy truncated strings
#
# Potential hash type later for OSM
# Vhash
# Authentihash
# Imphash
# Rich PE header hash
# SSDEEP https://ssdeep-project.github.io/ssdeep/index.html
# TLSH https://tlsh.org/
# TrID https://mark0.net/soft-trid-e.html
# Detect it Easy


def indicator_validation(
    type: Literal[
        "email",
        "url",
        "domain",
        "ip",
        "ip::v6",
        "uuid",
        "hash::md5",
        "hash::sha1",
        "hash::sha256",
        "hash::sha512",
    ],
    value,
    verbose: bool = True,
) -> bool:

    EMAIL_REGEX = r"^([a-z0-9_\.-]+\@[\da-z\.-]+\.[a-z\.]{2,6})$"
    URL_REGEX = r"(((ftp|http|https):\/\/)|(\/)|(..\/))(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?"
    DOMAIN_REGEX = r"(?=^.{1,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
    UUID_REGEX = (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    IP_REGEX = r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$"
    IPV6_REGEX = (
        r"^((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})$"
    )
    HASH_REGEX = r"^[a-fA-F0-9]{{{}}}$"  # Hash length set based on digest type

    match type:  # Early return strategy for fast validation times
        case "email":
            if re.match(EMAIL_REGEX, value):
                return True
        case "url":
            if re.match(URL_REGEX, value):
                return True
        case "domain":
            if re.match(DOMAIN_REGEX, value):
                return True
        case "ip":
            if re.match(IP_REGEX, value):
                return True
        case "ip::v6":
            if re.match(IPV6_REGEX, value):
                return True
        case "uuid":
            if re.match(UUID_REGEX, value):
                return True
        case "hash::md5":
            if re.match(HASH_REGEX.format(32), value):
                return True
        case "hash::sha1":
            if re.match(HASH_REGEX.format(40), value):
                return True
        case "hash::sha256":
            if re.match(HASH_REGEX.format(64), value):
                return True
        case _:
            log("FATAL", "Indicators validation received invalid type", type)
            raise Exception("Invalid Type")

    if verbose:
        log(
            "FAILURE",
            f"The following value is not of type {type}",
            value,
            "Correct the value to the expected type.",
        )

    return False

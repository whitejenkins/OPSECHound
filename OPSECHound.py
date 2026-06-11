#!/usr/bin/env python3
"""
OPSECHound - OPSEC-friendly LDAP collector for BOFHound/BloodHound JSON.

The original BOFHound parses LDAP result logs. OPSECHound keeps the same idea
of operator-controlled LDAP collection, but performs the LDAP queries itself and
then runs a BOFHound-like post-processing pass:

- users, computers, groups, domains, OUs, GPOs, and optional containers
- group membership from member, memberOf, and primaryGroupID
- OU/domain child relationships
- GPO links from gPLink
- default well-known principals
- optional nTSecurityDescriptor collection and ACL parsing when the
  bloodhound Python package is installed

Install:
    pip3 install ldap3

Optional ACL parsing:
    pip3 install bloodhound
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from ldap3 import (
        Server,
        Connection,
        ALL,
        NTLM,
        SIMPLE,
        ANONYMOUS,
        SUBTREE,
        BASE,
        Tls,
    )
    from ldap3.core.exceptions import LDAPException

    LDAP3_IMPORT_ERROR: Optional[ImportError] = None
except ImportError as e:
    Server = Connection = Tls = None  # type: ignore[assignment]
    ALL = NTLM = SIMPLE = ANONYMOUS = SUBTREE = BASE = None  # type: ignore[assignment]

    class LDAPException(Exception):
        pass

    LDAP3_IMPORT_ERROR = e


BH_VERSION = 6
COLLECTOR_VERSION = "OPSECHound-0.2.0"

COLLECTION_METHOD_GROUP = 1
COLLECTION_METHOD_TRUSTS = 32
COLLECTION_METHOD_ACL = 64
COLLECTION_METHOD_CONTAINER = 128
COLLECTION_METHOD_OBJECT_PROPS = 512
COLLECTION_METHOD_SPN_TARGETS = 8192
DEFAULT_COLLECTION_METHODS = (
    COLLECTION_METHOD_GROUP
    | COLLECTION_METHOD_TRUSTS
    | COLLECTION_METHOD_CONTAINER
    | COLLECTION_METHOD_OBJECT_PROPS
    | COLLECTION_METHOD_SPN_TARGETS
)

BOFHOUND_OUTPUT_TYPES = ["domains", "computers", "users", "groups", "ous", "gpos"]
SUPPORTED_TYPES = BOFHOUND_OUTPUT_TYPES + ["containers"]

GROUP_SAM_TYPES = {268435456, 268435457, 536870912, 536870913}
USER_SAM_TYPES = {805306368}
COMPUTER_SAM_TYPES = {805306369}
TRUST_ACCOUNT_SAM_TYPES = {805306370}

MULTI_VALUE_ATTRIBUTES = {
    "objectclass",
    "member",
    "memberof",
    "serviceprincipalname",
    "sidhistory",
    "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity",
    "msds-groupmsamembership",
}

BINARY_ATTRIBUTES = {
    "objectsid",
    "objectguid",
    "schemaidguid",
    "ntsecuritydescriptor",
    "sidhistory",
    "msds-allowedtoactonbehalfofotheridentity",
    "msds-groupmsamembership",
}

NEVER_SHOW_PROPERTIES = {
    "ntsecuritydescriptor",
    "schemaidguid",
    "objectclass",
}

OPTIONAL_LAPS_ATTRIBUTES = [
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
]

OPTIONAL_ACL_ATTRIBUTES = [
    "nTSecurityDescriptor",
]

FUNCTIONAL_LEVELS = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
    8: "2025",
}

WELLKNOWN_SIDS: Dict[str, Tuple[str, str]] = {
    "S-1-0-0": ("NULL SID", "User"),
    "S-1-1-0": ("EVERYONE", "Group"),
    "S-1-2-0": ("LOCAL", "Group"),
    "S-1-3-0": ("CREATOR OWNER", "User"),
    "S-1-3-1": ("CREATOR GROUP", "Group"),
    "S-1-5-4": ("INTERACTIVE", "Group"),
    "S-1-5-6": ("SERVICE", "Group"),
    "S-1-5-7": ("ANONYMOUS LOGON", "User"),
    "S-1-5-9": ("ENTERPRISE DOMAIN CONTROLLERS", "Group"),
    "S-1-5-10": ("SELF", "User"),
    "S-1-5-11": ("AUTHENTICATED USERS", "Group"),
    "S-1-5-18": ("LOCAL SYSTEM", "User"),
    "S-1-5-19": ("LOCAL SERVICE", "User"),
    "S-1-5-20": ("NETWORK SERVICE", "User"),
    "S-1-5-32-544": ("ADMINISTRATORS", "Group"),
    "S-1-5-32-545": ("USERS", "Group"),
    "S-1-5-32-546": ("GUESTS", "Group"),
    "S-1-5-32-547": ("POWER USERS", "Group"),
    "S-1-5-32-548": ("ACCOUNT OPERATORS", "Group"),
    "S-1-5-32-549": ("SERVER OPERATORS", "Group"),
    "S-1-5-32-550": ("PRINT OPERATORS", "Group"),
    "S-1-5-32-551": ("BACKUP OPERATORS", "Group"),
    "S-1-5-32-552": ("REPLICATOR", "Group"),
    "S-1-5-32-555": ("REMOTE DESKTOP USERS", "Group"),
    "S-1-5-32-556": ("NETWORK CONFIGURATION OPERATORS", "Group"),
    "S-1-5-32-558": ("PERFORMANCE MONITOR USERS", "Group"),
    "S-1-5-32-559": ("PERFORMANCE LOG USERS", "Group"),
    "S-1-5-32-562": ("DISTRIBUTED COM USERS", "Group"),
    "S-1-5-32-568": ("IIS_IUSRS", "Group"),
    "S-1-5-32-569": ("CRYPTOGRAPHIC OPERATORS", "Group"),
    "S-1-5-32-573": ("EVENT LOG READERS", "Group"),
}


@dataclass
class SearchSpec:
    name: str
    search_base: str
    search_filter: str
    search_scope: Any
    attributes: List[str]


def require_ldap3() -> None:
    if LDAP3_IMPORT_ERROR is None:
        return

    print("[-] Missing dependency: ldap3", file=sys.stderr)
    print("    Install it with: pip3 install ldap3", file=sys.stderr)
    sys.exit(1)


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def first(value: Any, default: Any = None) -> Any:
    values = as_list(value)
    return values[0] if values else default


def unique_preserve_order(values: Iterable[Any]) -> List[Any]:
    seen = set()
    result = []
    for value in values:
        key = json.dumps(value, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def normalize_domain(domain: Optional[str], base_dn: Optional[str]) -> str:
    if domain:
        return domain.upper()

    if base_dn:
        parts = []
        for part in base_dn.split(","):
            part = part.strip()
            if part.upper().startswith("DC="):
                parts.append(part[3:])
        if parts:
            return ".".join(parts).upper()

    return "UNKNOWN.LOCAL"


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def ldap_domain_from_dn(dn: Optional[str]) -> Optional[str]:
    if not dn:
        return None
    parts = []
    for component in dn.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component[3:])
    if not parts:
        return None
    return ".".join(parts).upper()


def domain_component_from_dn(dn: Optional[str]) -> Optional[str]:
    if not dn:
        return None
    parts = []
    for component in dn.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component.upper())
    return ",".join(parts) if parts else None


def ldap_binary_string_to_bytes(value: str, expected_length: Optional[int] = None) -> Optional[bytes]:
    if not value:
        return None

    candidates: List[bytes] = []
    for encoding in ("latin-1", "cp1252", "cp1251"):
        try:
            candidate = value.encode(encoding)
        except UnicodeEncodeError:
            continue
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        if expected_length is not None and len(candidate) != expected_length:
            continue
        if expected_length is None and len(candidate) < 8:
            continue
        return candidate

    return None


def sid_bytes_to_str(raw_sid: Any) -> Optional[str]:
    if raw_sid is None:
        return None

    if isinstance(raw_sid, list):
        raw_sid = first(raw_sid)

    if isinstance(raw_sid, str):
        raw_sid = raw_sid.strip()
        if raw_sid.upper().startswith("S-"):
            return raw_sid.upper()

        recovered = ldap_binary_string_to_bytes(raw_sid)
        if recovered is None:
            return None
        raw_sid = recovered

    if not isinstance(raw_sid, (bytes, bytearray)):
        return str(raw_sid).upper()

    data = bytes(raw_sid)
    if len(data) < 8:
        return None

    revision = data[0]
    sub_auth_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    sub_auths = []
    offset = 8

    for _ in range(sub_auth_count):
        if offset + 4 > len(data):
            return None
        sub_auths.append(int.from_bytes(data[offset:offset + 4], byteorder="little"))
        offset += 4

    return "S-{}-{}-{}".format(
        revision,
        identifier_authority,
        "-".join(str(x) for x in sub_auths),
    ).upper()


def guid_bytes_to_str(raw_guid: Any) -> Optional[str]:
    if raw_guid is None:
        return None

    if isinstance(raw_guid, list):
        raw_guid = first(raw_guid)

    if isinstance(raw_guid, str):
        raw_guid = raw_guid.strip()
        try:
            return str(uuid.UUID(raw_guid.strip("{}"))).upper()
        except (ValueError, AttributeError):
            pass

        recovered = ldap_binary_string_to_bytes(raw_guid, expected_length=16)
        if recovered is None:
            return None
        raw_guid = recovered

    if not isinstance(raw_guid, (bytes, bytearray)):
        return str(raw_guid).upper()

    data = bytes(raw_guid)
    if len(data) != 16:
        return None

    return str(uuid.UUID(bytes_le=data)).upper()


def domain_sid_from_object_sid(sid: Optional[str]) -> Optional[str]:
    if not sid or not str(sid).upper().startswith("S-"):
        return None

    parts = str(sid).upper().split("-")
    if len(parts) <= 7:
        return str(sid).upper()

    return "-".join(parts[:-1]).upper()


def is_well_known_sid(sid: Optional[str]) -> bool:
    if not sid:
        return False
    sid = sid.upper()
    return sid in WELLKNOWN_SIDS or sid.startswith("S-1-5-32-")


def strip_domain_prefix_from_wellknown_sid(sid: str) -> str:
    marker = "-S-"
    if marker in sid and not sid.upper().startswith("S-"):
        return "S-" + sid.split(marker, 1)[1]
    return sid


def normalize_well_known_sid(sid: Optional[str], domain: str) -> Optional[str]:
    if not sid:
        return None

    sid = sid.upper()
    plain_sid = strip_domain_prefix_from_wellknown_sid(sid)

    if is_well_known_sid(plain_sid):
        return f"{domain.upper()}-{plain_sid}"

    return sid


def principal_type_from_sid(sid: str, sid_type_index: Dict[str, str]) -> str:
    normalized = sid.upper()
    if normalized in sid_type_index:
        return sid_type_index[normalized]

    plain = strip_domain_prefix_from_wellknown_sid(normalized)
    if plain in WELLKNOWN_SIDS:
        return WELLKNOWN_SIDS[plain][1]

    return "Base"


def int_value(value: Any, default: Optional[int] = None) -> Optional[int]:
    value = first(value)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def bool_attr(value: Any) -> bool:
    value = first(value)
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in {"1", "true", "yes"}


def generalized_time(value: Any) -> Any:
    value = first(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")
    return value


def generalized_time_to_unix(value: Any) -> Any:
    value = first(value)
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.astimezone(timezone.utc).timestamp())

    if isinstance(value, (int, float)):
        return int(value)

    text = str(value).strip()
    if not text:
        return None

    for pattern in ("%Y%m%d%H%M%S.%fZ", "%Y%m%d%H%M%SZ"):
        try:
            return int(datetime.strptime(text, pattern).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass

    try:
        return ad_filetime_to_unix(int(text))
    except ValueError:
        return value


def ad_filetime_to_unix(value: Any) -> Any:
    value = first(value)
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())

    try:
        raw = int(value)
    except (TypeError, ValueError):
        return value

    if raw == 0:
        return 0

    if raw > 116444736000000000:
        return int((raw - 116444736000000000) / 10000000)

    return raw


def get_attr(obj: Dict[str, Any], name: str, default: Any = None) -> Any:
    key = name.lower()
    if key in obj:
        return obj[key]
    return default


def set_if_present(props: Dict[str, Any], prop_name: str, value: Any) -> None:
    value = first(value)
    if value is not None and value != "":
        props[prop_name] = value


def normalize_single_ldap_value(attr: str, value: Any) -> Any:
    attr = attr.lower()

    if attr == "objectsid":
        return sid_bytes_to_str(value)

    if attr == "sidhistory":
        return sid_bytes_to_str(value)

    if attr in {"objectguid", "schemaidguid"}:
        return guid_bytes_to_str(value)

    if attr == "ntsecuritydescriptor":
        value = first(value)
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return base64.b64encode(bytes(value)).decode("ascii")
        return value

    if isinstance(value, datetime):
        return generalized_time(value)

    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(bytes(value)).decode("ascii")

    return value


def normalize_ldap_value(attr: str, value: Any) -> Any:
    attr = attr.lower()
    values = as_list(value)
    converted = [
        normalize_single_ldap_value(attr, item)
        for item in values
        if item is not None
    ]

    if attr in MULTI_VALUE_ATTRIBUTES:
        return converted

    if not converted:
        return None

    if len(converted) == 1:
        return converted[0]

    return converted


def entry_to_raw_object(entry: Any) -> Dict[str, Any]:
    raw: Dict[str, Any] = {}

    try:
        data = entry.entry_attributes_as_dict
    except Exception:
        data = {}

    try:
        raw_data = entry.entry_raw_attributes
    except Exception:
        raw_data = {}

    raw_data_by_lower = {str(attr).lower(): value for attr, value in raw_data.items()}

    for attr, value in data.items():
        lower_attr = attr.lower()
        if lower_attr in BINARY_ATTRIBUTES and lower_attr in raw_data_by_lower:
            value = raw_data_by_lower[lower_attr]
        raw[lower_attr] = normalize_ldap_value(attr, value)

    for lower_attr, value in raw_data_by_lower.items():
        if lower_attr in raw or lower_attr not in BINARY_ATTRIBUTES:
            continue
        raw[lower_attr] = normalize_ldap_value(lower_attr, value)

    entry_dn = getattr(entry, "entry_dn", None)
    if entry_dn:
        raw["distinguishedname"] = str(first(raw.get("distinguishedname"), entry_dn))

    return raw


def object_classes(obj: Dict[str, Any]) -> List[str]:
    values = []
    for item in as_list(get_attr(obj, "objectClass", [])):
        if isinstance(item, str) and (";" in item or "," in item):
            values.extend(part.strip() for part in re.split(r"[;,]", item) if part.strip())
        else:
            values.append(str(item))
    return [value.lower() for value in values]


def classify_object(obj: Dict[str, Any]) -> Optional[str]:
    if get_attr(obj, "schemaIDGUID") and get_attr(obj, "name"):
        return "schemas"

    sam_type = int_value(get_attr(obj, "sAMAccountType"))
    classes = object_classes(obj)

    if sam_type in GROUP_SAM_TYPES:
        return "groups"
    if sam_type in USER_SAM_TYPES:
        return "users"
    if sam_type in COMPUTER_SAM_TYPES:
        return "computers"
    if sam_type in TRUST_ACCOUNT_SAM_TYPES:
        return "trustaccounts"

    if "domaindns" in classes or ("domain" in classes and str(get_attr(obj, "distinguishedName", "")).upper().startswith("DC=")):
        return "domains"
    if "trusteddomain" in classes:
        return "trusts"
    if "grouppolicycontainer" in classes:
        return "gpos"
    if "organizationalunit" in classes:
        return "ous"
    if "computer" in classes:
        return "computers"
    if "group" in classes:
        return "groups"
    if "user" in classes or "person" in classes:
        return "users"
    if "container" in classes:
        return "containers"

    return None


def type_for_bh(json_type: str) -> str:
    mapping = {
        "domains": "Domain",
        "users": "User",
        "groups": "Group",
        "computers": "Computer",
        "ous": "OU",
        "gpos": "GPO",
        "containers": "Container",
    }
    return mapping.get(json_type, "Base")


def object_id_for_raw(obj: Dict[str, Any], domain: str) -> Optional[str]:
    sid = sid_bytes_to_str(get_attr(obj, "objectSid"))
    guid = guid_bytes_to_str(get_attr(obj, "objectGUID"))
    data_type = classify_object(obj)

    if sid:
        if data_type in {"groups", "users", "computers"}:
            return normalize_well_known_sid(sid, domain)
        return sid.upper()

    if guid:
        return guid.upper()

    dn = first(get_attr(obj, "distinguishedName"))
    if dn:
        return str(dn).upper()

    return None


def infer_domain_sid(objects: Sequence[Dict[str, Any]], domain: str) -> Optional[str]:
    for obj in objects:
        if classify_object(obj) == "domains":
            sid = sid_bytes_to_str(get_attr(obj, "objectSid"))
            if sid and not is_well_known_sid(sid):
                return sid.upper()

    for obj in objects:
        sid = sid_bytes_to_str(get_attr(obj, "objectSid"))
        if sid and sid.upper().startswith("S-1-5-21-"):
            return domain_sid_from_object_sid(sid)

    return None


def domain_sid_for_object(sid: Optional[str], inferred_domain_sid: Optional[str]) -> Optional[str]:
    if sid and sid.upper().startswith("S-1-5-21-"):
        return domain_sid_from_object_sid(sid)
    return inferred_domain_sid


def merge_raw_objects(objects: Sequence[Dict[str, Any]], domain: str) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        object_id = object_id_for_raw(obj, domain)
        dn = first(get_attr(obj, "distinguishedName"))
        key = object_id or (str(dn).upper() if dn else None)

        if not key:
            continue

        key = key.upper()
        if key not in merged:
            merged[key] = dict(obj)
            continue

        for attr, value in obj.items():
            if value is None or value == "" or value == []:
                continue
            merged[key][attr] = value

    return list(merged.values())


def json_safe_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return generalized_time(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, list):
        return [json_safe_value(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): json_safe_value(v) for k, v in value.items()}
    return value


def add_all_properties(props: Dict[str, Any], raw: Dict[str, Any]) -> None:
    for key, value in raw.items():
        lower_key = key.lower()
        if lower_key in NEVER_SHOW_PROPERTIES:
            continue
        if lower_key not in props and value not in (None, "", []):
            props[lower_key] = json_safe_value(value)


def parse_uac_properties(props: Dict[str, Any], raw: Dict[str, Any]) -> None:
    user_account_control = int_value(get_attr(raw, "userAccountControl"))
    if user_account_control is None:
        return

    props["useraccountcontrol"] = user_account_control
    props["enabled"] = (user_account_control & 0x2) == 0
    props["pwdneverexpires"] = bool(user_account_control & 0x10000)
    props["dontreqpreauth"] = bool(user_account_control & 0x400000)
    props["trustedtoauth"] = bool(user_account_control & 0x1000000)
    props["unconstraineddelegation"] = bool(user_account_control & 0x80000)
    props["passwordnotreqd"] = bool(user_account_control & 0x20)
    props["sensitive"] = bool(user_account_control & 0x100000)


def bh_base_properties(
    raw: Dict[str, Any],
    domain: str,
    object_sid: Optional[str],
    inferred_domain_sid: Optional[str],
    all_properties: bool,
) -> Dict[str, Any]:
    dn = str(first(get_attr(raw, "distinguishedName"), "")).upper()
    props: Dict[str, Any] = {
        "domain": domain.upper(),
        "distinguishedname": dn,
        "domainsid": domain_sid_for_object(object_sid, inferred_domain_sid),
    }

    set_if_present(props, "samaccountname", get_attr(raw, "sAMAccountName"))
    set_if_present(props, "description", get_attr(raw, "description"))
    set_if_present(props, "displayname", get_attr(raw, "displayName"))
    set_if_present(props, "email", get_attr(raw, "mail"))
    set_if_present(props, "title", get_attr(raw, "title"))
    set_if_present(props, "department", get_attr(raw, "department"))
    set_if_present(props, "whencreated", generalized_time_to_unix(get_attr(raw, "whenCreated")))

    admin_count = get_attr(raw, "adminCount")
    if admin_count is not None:
        props["admincount"] = bool_attr(admin_count)

    parse_uac_properties(props, raw)

    for source, target in [
        ("lastLogon", "lastlogon"),
        ("lastLogonTimestamp", "lastlogontimestamp"),
        ("pwdLastSet", "pwdlastset"),
    ]:
        converted = ad_filetime_to_unix(get_attr(raw, source))
        if converted is not None:
            props[target] = converted

    if all_properties:
        add_all_properties(props, raw)

    return props


def principal_name(raw: Dict[str, Any], domain: str) -> str:
    name = (
        first(get_attr(raw, "sAMAccountName"))
        or first(get_attr(raw, "cn"))
        or first(get_attr(raw, "name"))
        or first(get_attr(raw, "distinguishedName"))
        or "UNKNOWN"
    )
    return f"{str(name).upper()}@{domain.upper()}"


def computer_name(raw: Dict[str, Any], domain: str) -> str:
    dns = first(get_attr(raw, "dNSHostName"))
    if dns:
        return str(dns).upper()

    sam = first(get_attr(raw, "sAMAccountName"))
    if sam:
        sam = str(sam)
        if sam.endswith("$"):
            sam = sam[:-1]
        return f"{sam}.{domain}".upper()

    return principal_name(raw, domain)


def ou_name(raw: Dict[str, Any], domain: str) -> str:
    name = first(get_attr(raw, "ou")) or first(get_attr(raw, "name")) or first(get_attr(raw, "cn")) or first(get_attr(raw, "distinguishedName")) or "UNKNOWN"
    return f"{str(name).upper()}@{domain.upper()}"


def gpo_name(raw: Dict[str, Any], domain: str) -> str:
    name = first(get_attr(raw, "displayName")) or first(get_attr(raw, "name")) or first(get_attr(raw, "cn")) or first(get_attr(raw, "distinguishedName")) or "UNKNOWN"
    return f"{str(name).upper()}@{domain.upper()}"


def primary_group_sid(raw: Dict[str, Any]) -> Optional[str]:
    sid = sid_bytes_to_str(get_attr(raw, "objectSid"))
    primary_group_id = first(get_attr(raw, "primaryGroupID"))
    if not sid or primary_group_id in (None, ""):
        return None

    domain_sid = domain_sid_from_object_sid(sid)
    if not domain_sid:
        return None

    return f"{domain_sid}-{primary_group_id}".upper()


def as_strings(value: Any) -> List[str]:
    return [str(item) for item in as_list(value) if item is not None and str(item) != ""]


def sid_history_values(raw: Dict[str, Any]) -> List[str]:
    result = []
    for sid in as_list(get_attr(raw, "sIDHistory", [])):
        normalized = sid_bytes_to_str(sid)
        if normalized:
            result.append(normalized)
    return result


def typed_principal(object_identifier: str, object_type: str = "Base") -> Dict[str, str]:
    return {
        "ObjectIdentifier": str(object_identifier).upper(),
        "ObjectType": object_type,
    }


def sid_history_refs(raw: Dict[str, Any], domain: str) -> List[Dict[str, str]]:
    refs = []
    for sid in sid_history_values(raw):
        principal_sid = normalize_well_known_sid(sid, domain) or sid.upper()
        refs.append(typed_principal(principal_sid, principal_type_from_sid(principal_sid, {})))
    return unique_preserve_order(refs)


def domain_sid_or_inferred(raw_sid: Optional[str], inferred_domain_sid: Optional[str]) -> Optional[str]:
    domain_sid = domain_sid_for_object(raw_sid, inferred_domain_sid)
    return domain_sid.upper() if domain_sid else None


def is_domain_controller(raw: Dict[str, Any]) -> bool:
    primary = str(first(get_attr(raw, "primaryGroupID"), "")).strip()
    user_account_control = int_value(get_attr(raw, "userAccountControl"), 0) or 0
    return primary == "516" or bool(user_account_control & 0x2000)


def not_collected_result() -> Dict[str, Any]:
    return {"Collected": False, "FailureReason": None, "Results": []}


def empty_dc_registry_data() -> Dict[str, Any]:
    return {
        "CertificateMappingMethods": {"Collected": False, "FailureReason": None},
        "StrongCertificateBindingEnforcement": {"Collected": False, "FailureReason": None},
        "VulnerableNetlogonSecurityDescriptor": {"Collected": False, "FailureReason": None},
    }


def make_user(
    raw: Dict[str, Any],
    domain: str,
    inferred_domain_sid: Optional[str],
    all_properties: bool,
) -> Optional[Dict[str, Any]]:
    sid = object_id_for_raw(raw, domain)
    if not sid:
        return None

    raw_sid = sid_bytes_to_str(get_attr(raw, "objectSid"))
    props = bh_base_properties(raw, domain, raw_sid, inferred_domain_sid, all_properties)
    props["name"] = principal_name(raw, domain)
    props["domain"] = domain.upper()

    spns = as_strings(get_attr(raw, "servicePrincipalName", []))
    props["serviceprincipalnames"] = spns
    if spns:
        props["hasspn"] = True

    delegates = as_strings(get_attr(raw, "msDS-AllowedToDelegateTo", []))
    if delegates:
        props["allowedtodelegate"] = delegates

    sid_history = sid_history_values(raw)
    sid_history_links = sid_history_refs(raw, domain)
    if sid_history:
        props["sidhistory"] = sid_history

    return {
        "ObjectIdentifier": sid.upper(),
        "AllowedToDelegate": delegates,
        "PrimaryGroupSID": primary_group_sid(raw),
        "Properties": props,
        "Aces": [],
        "SPNTargets": [],
        "HasSIDHistory": sid_history_links,
        "UnconstrainedDelegation": bool(props.get("unconstraineddelegation")),
        "DomainSID": domain_sid_or_inferred(raw_sid, inferred_domain_sid),
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def make_computer(
    raw: Dict[str, Any],
    domain: str,
    inferred_domain_sid: Optional[str],
    all_properties: bool,
) -> Optional[Dict[str, Any]]:
    sid = object_id_for_raw(raw, domain)
    if not sid:
        return None

    raw_sid = sid_bytes_to_str(get_attr(raw, "objectSid"))
    props = bh_base_properties(raw, domain, raw_sid, inferred_domain_sid, all_properties)
    props["name"] = computer_name(raw, domain)
    props["domain"] = domain.upper()
    props["objectid"] = sid.upper()
    props["highvalue"] = False

    set_if_present(props, "dnshostname", get_attr(raw, "dNSHostName"))

    operating_system = first(get_attr(raw, "operatingSystem"))
    service_pack = first(get_attr(raw, "operatingSystemServicePack"))
    if operating_system and service_pack:
        props["operatingsystem"] = f"{operating_system} {service_pack}"
    elif operating_system:
        props["operatingsystem"] = operating_system

    laps_expiration = first(get_attr(raw, "ms-Mcs-AdmPwdExpirationTime"))
    windows_laps_expiration = first(get_attr(raw, "msLAPS-PasswordExpirationTime"))
    if laps_expiration or windows_laps_expiration:
        props["haslaps"] = True

    spns = as_strings(get_attr(raw, "servicePrincipalName", []))
    if spns:
        props["serviceprincipalnames"] = spns

    delegates = as_strings(get_attr(raw, "msDS-AllowedToDelegateTo", []))
    if delegates:
        props["allowedtodelegate"] = delegates

    sid_history = sid_history_values(raw)
    sid_history_links = sid_history_refs(raw, domain)
    if sid_history:
        props["sidhistory"] = sid_history

    return {
        "Sessions": not_collected_result(),
        "PrivilegedSessions": not_collected_result(),
        "RegistrySessions": not_collected_result(),
        "LocalGroups": [],
        "UserRights": [],
        "DCRegistryData": empty_dc_registry_data(),
        "Status": None,
        "Aces": [],
        "IsACLProtected": False,
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "ObjectIdentifier": sid.upper(),
        "PrimaryGroupSID": primary_group_sid(raw),
        "AllowedToDelegate": delegates,
        "AllowedToAct": [],
        "HasSIDHistory": sid_history_links,
        "DumpSMSAPassword": [],
        "IsDC": is_domain_controller(raw),
        "UnconstrainedDelegation": bool(props.get("unconstraineddelegation")),
        "DomainSID": domain_sid_or_inferred(raw_sid, inferred_domain_sid),
        "Properties": props,
    }


def make_group(
    raw: Dict[str, Any],
    domain: str,
    inferred_domain_sid: Optional[str],
    all_properties: bool,
) -> Optional[Dict[str, Any]]:
    sid = object_id_for_raw(raw, domain)
    if not sid:
        return None

    raw_sid = sid_bytes_to_str(get_attr(raw, "objectSid"))
    props = bh_base_properties(raw, domain, raw_sid, inferred_domain_sid, all_properties)
    props["name"] = principal_name(raw, domain)
    props["domain"] = domain.upper()
    sid_history = sid_history_values(raw)
    sid_history_links = sid_history_refs(raw, domain)
    if sid_history:
        props["sidhistory"] = sid_history

    return {
        "ObjectIdentifier": sid.upper(),
        "Properties": props,
        "Aces": [],
        "Members": [],
        "HasSIDHistory": sid_history_links,
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def make_domain(raw: Dict[str, Any], domain: str, all_properties: bool) -> Optional[Dict[str, Any]]:
    sid = sid_bytes_to_str(get_attr(raw, "objectSid"))
    dn = first(get_attr(raw, "distinguishedName"))

    if not sid:
        return None

    domain_name = ldap_domain_from_dn(str(dn)) or domain.upper()
    props: Dict[str, Any] = {
        "name": domain_name.upper(),
        "domain": domain_name.upper(),
        "objectid": sid.upper(),
        "distinguishedname": str(dn).upper() if dn else domain_to_dn(domain_name).upper(),
        "highvalue": True,
        "functionallevel": FUNCTIONAL_LEVELS.get(
            int_value(get_attr(raw, "msDS-Behavior-Version"), -1),
            "Unknown",
        ),
    }

    set_if_present(props, "description", get_attr(raw, "description"))
    set_if_present(props, "whencreated", generalized_time_to_unix(get_attr(raw, "whenCreated")))

    if all_properties:
        add_all_properties(props, raw)

    return {
        "ObjectIdentifier": sid.upper(),
        "Properties": props,
        "Trusts": [],
        "Aces": [],
        "Links": [],
        "ChildObjects": [],
        "InheritanceHashes": [],
        "ForestRootIdentifier": sid.upper(),
        "GPOChanges": {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": [],
        },
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def make_synthetic_domain(domain: str, base_dn: str, inferred_domain_sid: Optional[str]) -> Optional[Dict[str, Any]]:
    if not inferred_domain_sid:
        return None

    props = {
        "name": domain.upper(),
        "domain": domain.upper(),
        "objectid": inferred_domain_sid.upper(),
        "distinguishedname": base_dn.upper(),
        "highvalue": True,
        "functionallevel": "Unknown",
    }

    return {
        "ObjectIdentifier": inferred_domain_sid.upper(),
        "Properties": props,
        "Trusts": [],
        "Aces": [],
        "Links": [],
        "ChildObjects": [],
        "InheritanceHashes": [],
        "ForestRootIdentifier": inferred_domain_sid.upper(),
        "GPOChanges": {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": [],
        },
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def make_ou(raw: Dict[str, Any], domain: str, inferred_domain_sid: Optional[str], all_properties: bool) -> Optional[Dict[str, Any]]:
    guid = guid_bytes_to_str(get_attr(raw, "objectGUID"))
    if not guid:
        return None

    dn = str(first(get_attr(raw, "distinguishedName"), "")).upper()
    props: Dict[str, Any] = {
        "distinguishedname": dn,
        "domain": (ldap_domain_from_dn(dn) or domain).upper(),
        "domainsid": inferred_domain_sid,
        "name": ou_name(raw, domain),
        "highvalue": False,
        "blocksinheritance": str(first(get_attr(raw, "gPOptions"), "0")) == "1",
    }

    set_if_present(props, "description", get_attr(raw, "description"))
    set_if_present(props, "whencreated", generalized_time_to_unix(get_attr(raw, "whenCreated")))

    if all_properties:
        add_all_properties(props, raw)

    return {
        "ObjectIdentifier": guid.upper(),
        "Properties": props,
        "Aces": [],
        "Links": [],
        "ChildObjects": [],
        "InheritanceHashes": [],
        "GPOChanges": {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": [],
        },
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def make_gpo(raw: Dict[str, Any], domain: str, all_properties: bool) -> Optional[Dict[str, Any]]:
    guid = guid_bytes_to_str(get_attr(raw, "objectGUID"))
    if not guid:
        return None

    dn = str(first(get_attr(raw, "distinguishedName"), "")).upper()
    props: Dict[str, Any] = {
        "distinguishedname": dn,
        "domain": (ldap_domain_from_dn(dn) or domain).upper(),
        "name": gpo_name(raw, domain),
        "highvalue": False,
    }

    set_if_present(props, "description", get_attr(raw, "description"))
    set_if_present(props, "whencreated", generalized_time_to_unix(get_attr(raw, "whenCreated")))
    set_if_present(props, "gpcpath", get_attr(raw, "gPCFileSysPath"))

    if all_properties:
        add_all_properties(props, raw)

    return {
        "ObjectIdentifier": guid.upper(),
        "Properties": props,
        "Aces": [],
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def make_container(raw: Dict[str, Any], domain: str, inferred_domain_sid: Optional[str], all_properties: bool) -> Optional[Dict[str, Any]]:
    guid = guid_bytes_to_str(get_attr(raw, "objectGUID"))
    dn = str(first(get_attr(raw, "distinguishedName"), "")).upper()
    object_identifier = guid or dn

    if not object_identifier:
        return None

    props: Dict[str, Any] = {
        "distinguishedname": dn,
        "domain": (ldap_domain_from_dn(dn) or domain).upper(),
        "domainsid": inferred_domain_sid,
        "name": principal_name(raw, domain),
    }

    set_if_present(props, "description", get_attr(raw, "description"))
    set_if_present(props, "whencreated", generalized_time_to_unix(get_attr(raw, "whenCreated")))

    if all_properties:
        add_all_properties(props, raw)

    return {
        "ObjectIdentifier": object_identifier.upper(),
        "Properties": props,
        "Aces": [],
        "ChildObjects": [],
        "InheritanceHashes": [],
        "IsDeleted": bool_attr(get_attr(raw, "isDeleted")),
        "IsACLProtected": False,
    }


def object_ref(obj: Dict[str, Any], object_type: str) -> Dict[str, str]:
    return {
        "ObjectIdentifier": str(obj["ObjectIdentifier"]).upper(),
        "ObjectType": object_type,
    }


def append_unique_ref(target: List[Dict[str, str]], ref: Optional[Dict[str, str]]) -> None:
    if not ref:
        return
    if ref not in target:
        target.append(ref)


def build_output_indexes(converted: Dict[str, List[Dict[str, Any]]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, str]]:
    by_oid: Dict[str, Dict[str, Any]] = {}
    by_dn: Dict[str, Dict[str, Any]] = {}
    sid_type_index: Dict[str, str] = {}

    for data_type, object_type in [
        ("domains", "Domain"),
        ("users", "User"),
        ("groups", "Group"),
        ("computers", "Computer"),
        ("ous", "OU"),
        ("gpos", "GPO"),
        ("containers", "Container"),
    ]:
        for obj in converted.get(data_type, []):
            oid = str(obj.get("ObjectIdentifier", "")).upper()
            if oid:
                by_oid[oid] = obj
                sid_type_index[oid] = object_type
            dn = str(obj.get("Properties", {}).get("distinguishedname", "")).upper()
            if dn:
                by_dn[dn] = obj

    return by_oid, by_dn, sid_type_index


def resolve_group_members(converted: Dict[str, List[Dict[str, Any]]], raw_objects: Sequence[Dict[str, Any]], domain: str) -> None:
    _, by_dn, _ = build_output_indexes(converted)

    def ref_from_raw(raw: Dict[str, Any]) -> Optional[Dict[str, str]]:
        data_type = classify_object(raw)
        if data_type not in {"users", "groups", "computers"}:
            return None
        oid = object_id_for_raw(raw, domain)
        if not oid:
            return None
        return {"ObjectIdentifier": oid.upper(), "ObjectType": type_for_bh(data_type)}

    group_by_dn = {}
    group_by_oid = {}
    for group in converted.get("groups", []):
        dn = str(group.get("Properties", {}).get("distinguishedname", "")).upper()
        oid = str(group.get("ObjectIdentifier", "")).upper()
        if dn:
            group_by_dn[dn] = group
        if oid:
            group_by_oid[oid] = group

    for raw in raw_objects:
        if classify_object(raw) == "groups":
            group_oid = object_id_for_raw(raw, domain)
            if not group_oid:
                continue
            group = group_by_oid.get(group_oid.upper())
            if not group:
                continue
            for member_dn in as_strings(get_attr(raw, "member", [])):
                member = by_dn.get(member_dn.upper())
                if not member:
                    continue
                member_type = None
                for data_type in ["users", "groups", "computers", "ous", "gpos", "containers", "domains"]:
                    if member in converted.get(data_type, []):
                        member_type = type_for_bh(data_type)
                        break
                if member_type:
                    append_unique_ref(group["Members"], object_ref(member, member_type))

    for raw in raw_objects:
        member_ref = ref_from_raw(raw)
        if not member_ref:
            continue

        for group_dn in as_strings(get_attr(raw, "memberOf", [])):
            group = group_by_dn.get(group_dn.upper())
            if group:
                append_unique_ref(group["Members"], member_ref)

        pg_sid = primary_group_sid(raw)
        if pg_sid:
            group = group_by_oid.get(pg_sid.upper())
            if group:
                append_unique_ref(group["Members"], member_ref)

    for group in converted.get("groups", []):
        group["Members"] = unique_preserve_order(group.get("Members", []))


def resolve_ou_members(converted: Dict[str, List[Dict[str, Any]]]) -> None:
    _, by_dn, _ = build_output_indexes(converted)

    def nearest_ou_dn(dn: str) -> Optional[str]:
        if "OU=" not in dn:
            return None
        return "OU=" + dn.split("OU=", 1)[1]

    for data_type, object_type in [
        ("users", "User"),
        ("groups", "Group"),
        ("computers", "Computer"),
    ]:
        for obj in converted.get(data_type, []):
            dn = str(obj.get("Properties", {}).get("distinguishedname", "")).upper()
            target_ou_dn = nearest_ou_dn(dn)
            if not target_ou_dn:
                continue
            ou = by_dn.get(target_ou_dn)
            if ou:
                append_unique_ref(ou.setdefault("ChildObjects", []), object_ref(obj, object_type))

    for nested_ou in converted.get("ous", []):
        dn = str(nested_ou.get("Properties", {}).get("distinguishedname", "")).upper()
        parent = None

        if len(dn.split("OU=")) > 2:
            target_ou_dn = "OU=" + dn.split("OU=", 2)[2]
            parent = by_dn.get(target_ou_dn)
        else:
            domain_dn = domain_component_from_dn(dn)
            if domain_dn:
                parent = by_dn.get(domain_dn)

        if parent:
            append_unique_ref(parent.setdefault("ChildObjects", []), object_ref(nested_ou, "OU"))


def parse_gplink(value: Any) -> List[Tuple[str, str]]:
    text = str(first(value, ""))
    if not text:
        return []

    text = text.replace("LDAP//", "LDAP://")
    links = []
    for dn, options in re.findall(r"\[LDAP://([^;\]]+);(\d+)\]", text, flags=re.IGNORECASE):
        links.append((dn.upper(), options))
    return links


def link_gpos(converted: Dict[str, List[Dict[str, Any]]], raw_by_oid: Dict[str, Dict[str, Any]], domain: str) -> None:
    _, by_dn, _ = build_output_indexes(converted)

    for data_type in ["domains", "ous"]:
        for obj in converted.get(data_type, []):
            raw = raw_by_oid.get(str(obj.get("ObjectIdentifier", "")).upper(), {})
            for gpo_dn, options in parse_gplink(get_attr(raw, "gPLink")):
                gpo = by_dn.get(gpo_dn)
                if not gpo:
                    continue
                link = {
                    "GUID": str(gpo.get("ObjectIdentifier", "")).upper(),
                    "IsEnforced": options == "2",
                }
                if link not in obj.setdefault("Links", []):
                    obj["Links"].append(link)


def resolve_delegation_targets(converted: Dict[str, List[Dict[str, Any]]]) -> None:
    computer_targets: Dict[str, str] = {}

    for computer in converted.get("computers", []):
        oid = str(computer.get("ObjectIdentifier", "")).upper()
        props = computer.get("Properties", {})
        for value in [
            props.get("name"),
            props.get("dnshostname"),
            props.get("samaccountname"),
        ]:
            if value:
                computer_targets[str(value).lower().rstrip("$")] = oid

    for data_type in ["users", "computers"]:
        for obj in converted.get(data_type, []):
            delegates = as_strings(obj.get("AllowedToDelegate", []))
            if not delegates:
                continue

            resolved: List[Dict[str, str]] = []
            for delegate in delegates:
                try:
                    target = delegate.split("/", 1)[1].split("/", 1)[0]
                except IndexError:
                    target = delegate
                key = target.lower().rstrip("$")
                target_oid = computer_targets.get(key)
                if target_oid:
                    resolved.append(typed_principal(target_oid, "Computer"))

            obj["AllowedToDelegate"] = unique_preserve_order(resolved)


def trust_direction(value: Any) -> str:
    mapping = {
        0: "Disabled",
        1: "Inbound",
        2: "Outbound",
        3: "Bidirectional",
    }
    return mapping.get(int_value(value, -1), "Unknown")


def trust_type(value: Any) -> str:
    mapping = {
        1: "Windows NT",
        2: "Active Directory",
        3: "MIT",
        4: "DCE",
    }
    return mapping.get(int_value(value, -1), "Unknown")


def trust_to_output(raw: Dict[str, Any], index: int, domain_map: Dict[str, str]) -> Optional[Tuple[str, Dict[str, Any]]]:
    required = ["distinguishedName", "trustPartner", "trustDirection", "trustType", "trustAttributes"]
    if any(get_attr(raw, attr) is None for attr in required):
        return None

    dn = str(first(get_attr(raw, "distinguishedName"))).upper()
    local_domain_dn = domain_component_from_dn(dn)
    target_domain = str(first(get_attr(raw, "trustPartner"))).upper()
    trust_attributes = int_value(get_attr(raw, "trustAttributes"), 0) or 0
    target_domain_dn = domain_to_dn(target_domain).upper()

    trust = {
        "TargetDomainName": target_domain,
        "TargetDomainSid": domain_map.get(target_domain_dn, f"S-1-5-21-{index}"),
        "IsTransitive": (trust_attributes & 0x1) == 0,
        "TrustDirection": trust_direction(get_attr(raw, "trustDirection")),
        "TrustType": trust_type(get_attr(raw, "trustType")),
        "SidFilteringEnabled": bool(trust_attributes & 0x4),
    }

    return local_domain_dn or "", trust


def resolve_domain_trusts(converted: Dict[str, List[Dict[str, Any]]], raw_objects: Sequence[Dict[str, Any]]) -> None:
    domain_map = {}
    domain_by_dn = {}
    for domain in converted.get("domains", []):
        dn = str(domain.get("Properties", {}).get("distinguishedname", "")).upper()
        oid = str(domain.get("ObjectIdentifier", "")).upper()
        if dn and oid:
            domain_map[dn] = oid
            domain_by_dn[dn] = domain

    index = 0
    for raw in raw_objects:
        if classify_object(raw) != "trusts":
            continue
        parsed = trust_to_output(raw, index, domain_map)
        index += 1
        if not parsed:
            continue
        local_domain_dn, trust = parsed
        domain = domain_by_dn.get(local_domain_dn)
        if not domain:
            continue
        if not any(existing.get("TargetDomainName") == trust["TargetDomainName"] for existing in domain.get("Trusts", [])):
            domain.setdefault("Trusts", []).append(trust)


def add_default_principals(converted: Dict[str, List[Dict[str, Any]]]) -> None:
    existing_user_oids = {str(obj.get("ObjectIdentifier", "")).upper() for obj in converted.get("users", [])}
    existing_group_oids = {str(obj.get("ObjectIdentifier", "")).upper() for obj in converted.get("groups", [])}

    for domain_obj in converted.get("domains", []):
        props = domain_obj.get("Properties", {})
        domain_name = str(props.get("name") or props.get("domain") or "UNKNOWN.LOCAL").upper()
        domain_sid = str(domain_obj.get("ObjectIdentifier", "")).upper()
        domain_dn = domain_to_dn(domain_name).upper()

        user_oid = f"{domain_name}-S-1-5-20"
        if user_oid not in existing_user_oids:
            converted.setdefault("users", []).append({
                "ObjectIdentifier": user_oid,
                "AllowedToDelegate": [],
                "PrimaryGroupSID": None,
                "Properties": {
                    "domain": domain_name,
                    "domainsid": domain_sid,
                    "name": f"NT AUTHORITY@{domain_name}",
                    "distinguishedname": f"CN=S-1-5-20,CN=FOREIGNSECURITYPRINCIPALS,{domain_dn}",
                },
                "Aces": [],
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            })
            existing_user_oids.add(user_oid)

        dc_members = []
        for computer in converted.get("computers", []):
            primary = str(computer.get("PrimaryGroupSID") or "").upper()
            if primary == f"{domain_sid}-516":
                dc_members.append(object_ref(computer, "Computer"))

        default_groups = [
            (f"{domain_name}-S-1-5-9", "ENTERPRISE DOMAIN CONTROLLERS", None, dc_members),
            (f"{domain_name}-S-1-1-0", "EVERYONE", domain_sid, []),
            (f"{domain_name}-S-1-5-11", "AUTHENTICATED USERS", domain_sid, []),
            (f"{domain_name}-S-1-5-4", "INTERACTIVE", domain_sid, []),
        ]

        for oid, name, maybe_domain_sid, members in default_groups:
            if oid in existing_group_oids:
                continue

            group_props = {
                "domain": domain_name,
                "name": f"{name}@{domain_name}",
                "distinguishedname": f"CN={oid.split('-', 1)[1]},CN=FOREIGNSECURITYPRINCIPALS,{domain_dn}",
            }
            if maybe_domain_sid:
                group_props["domainsid"] = maybe_domain_sid

            converted.setdefault("groups", []).append({
                "ObjectIdentifier": oid,
                "Properties": group_props,
                "Aces": [],
                "Members": members,
                "IsDeleted": False,
                "IsACLProtected": False,
            })
            existing_group_oids.add(oid)


def build_schema_guid_map(raw_objects: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    mapping = {}
    for raw in raw_objects:
        if classify_object(raw) != "schemas":
            continue
        name = first(get_attr(raw, "name")) or first(get_attr(raw, "lDAPDisplayName"))
        guid = guid_bytes_to_str(get_attr(raw, "schemaIDGUID"))
        if name and guid:
            mapping[str(name).lower()] = guid.lower()
    return mapping


def parse_acl_edges(converted: Dict[str, List[Dict[str, Any]]], raw_by_oid: Dict[str, Dict[str, Any]], schema_guid_map: Dict[str, str], domain: str) -> None:
    try:
        from bloodhound.enumeration.acls import (  # type: ignore
            SecurityDescriptor,
            ACCESS_MASK,
            ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
            EXTRIGHTS_GUID_MAPPING,
            has_extended_right,
            can_write_property,
            ace_applies,
        )
    except ImportError:
        print("[!] --parse-acls requested, but the bloodhound package is not installed.", file=sys.stderr)
        print("    Install optional support with: pip3 install bloodhound", file=sys.stderr)
        return

    _, _, sid_type_index = build_output_indexes(converted)
    ignored_sids = {"S-1-3-0", "S-1-5-18", "S-1-5-10"}

    def build_relation(target: Dict[str, Any], sid: str, right: str, inherited: bool) -> Dict[str, Any]:
        principal_sid = normalize_well_known_sid(sid, domain) or sid.upper()
        return {
            "RightName": right,
            "PrincipalSID": principal_sid,
            "IsInherited": inherited,
            "PrincipalType": principal_type_from_sid(principal_sid, sid_type_index),
        }

    def parse_one(target: Dict[str, Any], entry_type: str, raw_acl: Any) -> List[Dict[str, Any]]:
        try:
            if isinstance(raw_acl, str):
                value = base64.b64decode(raw_acl)
            elif isinstance(raw_acl, (bytes, bytearray)):
                value = bytes(raw_acl)
            else:
                return []
            sd = SecurityDescriptor(BytesIO(value))
        except Exception:
            return []

        target["IsACLProtected"] = bool(sd.has_control(sd.PD))
        relations = []

        owner_sid = str(sd.owner_sid)
        if owner_sid not in ignored_sids:
            relations.append(build_relation(target, owner_sid, "Owns", False))

        for ace_object in sd.dacl.aces:
            if ace_object.ace.AceType not in (0x00, 0x05):
                continue

            sid = str(ace_object.acedata.sid)
            if sid in ignored_sids:
                continue

            inherited = ace_object.has_flag(ACE.INHERITED_ACE)
            if not inherited and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                continue

            mask = ace_object.acedata.mask

            if ace_object.ace.AceType == 0x05:
                if inherited and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    try:
                        if not ace_applies(ace_object.acedata.get_inherited_object_type().lower(), entry_type, schema_guid_map):
                            continue
                    except KeyError:
                        pass

                if mask.has_priv(ACCESS_MASK.GENERIC_ALL) or mask.has_priv(ACCESS_MASK.WRITE_DACL) or mask.has_priv(ACCESS_MASK.WRITE_OWNER) or mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                    try:
                        if ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and not ace_applies(ace_object.acedata.get_object_type().lower(), entry_type, schema_guid_map):
                            continue
                    except KeyError:
                        pass

                    if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                        if (
                            entry_type == "computer"
                            and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT)
                            and target.get("Properties", {}).get("haslaps")
                            and "ms-mcs-admpwd" in schema_guid_map
                            and ace_object.acedata.get_object_type().lower() == schema_guid_map["ms-mcs-admpwd"]
                        ):
                            relations.append(build_relation(target, sid, "ReadLAPSPassword", inherited))
                        else:
                            relations.append(build_relation(target, sid, "GenericAll", inherited))
                        continue

                    if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                        relations.append(build_relation(target, sid, "GenericWrite", inherited))
                        if entry_type not in {"domain", "computer"}:
                            continue

                    if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                        relations.append(build_relation(target, sid, "WriteDacl", inherited))

                    if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                        relations.append(build_relation(target, sid, "WriteOwner", inherited))

                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                    if entry_type in {"user", "group", "computer", "gpo"} and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(build_relation(target, sid, "GenericWrite", inherited))
                    if entry_type == "group" and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING["WriteMember"]):
                        relations.append(build_relation(target, sid, "AddMember", inherited))
                    if entry_type == "computer" and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING["AllowedToAct"]):
                        relations.append(build_relation(target, sid, "AddAllowedToAct", inherited))
                    if entry_type == "computer" and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING["UserAccountRestrictionsSet"]) and not sid.endswith("-512"):
                        relations.append(build_relation(target, sid, "WriteAccountRestrictions", inherited))
                    if entry_type in {"user", "computer"} and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and "ms-ds-key-credential-link" in schema_guid_map and ace_object.acedata.get_object_type().lower() == schema_guid_map["ms-ds-key-credential-link"]:
                        relations.append(build_relation(target, sid, "AddKeyCredentialLink", inherited))
                    if entry_type == "user" and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and ace_object.acedata.get_object_type().lower() == "f3a64788-5306-11d1-a9c5-0000f80367c1":
                        relations.append(build_relation(target, sid, "WriteSPN", inherited))

                elif mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_SELF):
                    if entry_type == "group" and ace_object.acedata.data.ObjectType == EXTRIGHTS_GUID_MAPPING["WriteMember"]:
                        relations.append(build_relation(target, sid, "AddSelf", inherited))

                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_READ_PROP):
                    if (
                        entry_type == "computer"
                        and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT)
                        and target.get("Properties", {}).get("haslaps")
                        and "ms-mcs-admpwd" in schema_guid_map
                        and ace_object.acedata.get_object_type().lower() == schema_guid_map["ms-mcs-admpwd"]
                    ):
                        relations.append(build_relation(target, sid, "ReadLAPSPassword", inherited))

                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                    if entry_type in {"user", "domain", "computer"} and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(build_relation(target, sid, "AllExtendedRights", inherited))
                    if entry_type == "domain" and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING["GetChanges"]):
                        relations.append(build_relation(target, sid, "GetChanges", inherited))
                    if entry_type == "domain" and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING["GetChangesAll"]):
                        relations.append(build_relation(target, sid, "GetChangesAll", inherited))
                    if entry_type == "domain" and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING["GetChangesInFilteredSet"]):
                        relations.append(build_relation(target, sid, "GetChangesInFilteredSet", inherited))
                    if entry_type == "user" and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING["UserForceChangePassword"]):
                        relations.append(build_relation(target, sid, "ForceChangePassword", inherited))

            elif ace_object.ace.AceType == 0x00:
                if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                    relations.append(build_relation(target, sid, "GenericAll", inherited))
                    continue
                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP) and entry_type in {"user", "group", "computer", "gpo"}:
                    relations.append(build_relation(target, sid, "GenericWrite", inherited))
                if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                    relations.append(build_relation(target, sid, "WriteOwner", inherited))
                if entry_type in {"user", "domain"} and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                    relations.append(build_relation(target, sid, "AllExtendedRights", inherited))
                if entry_type == "computer" and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS) and sid != "S-1-5-32-544" and not sid.endswith("-512"):
                    relations.append(build_relation(target, sid, "AllExtendedRights", inherited))
                if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                    relations.append(build_relation(target, sid, "WriteDacl", inherited))

        return unique_preserve_order(relations)

    for data_type, entry_type in [
        ("domains", "domain"),
        ("users", "user"),
        ("groups", "group"),
        ("computers", "computer"),
        ("ous", "ou"),
        ("gpos", "gpo"),
        ("containers", "container"),
    ]:
        for obj in converted.get(data_type, []):
            oid = str(obj.get("ObjectIdentifier", "")).upper()
            raw = raw_by_oid.get(oid, {})
            raw_acl = get_attr(raw, "nTSecurityDescriptor")
            if not raw_acl:
                continue
            obj["Aces"] = parse_one(obj, entry_type, raw_acl)


def convert(
    raw_objects: Sequence[Dict[str, Any]],
    domain: str,
    base_dn: str,
    all_properties: bool = False,
    default_principals: bool = True,
    parse_acls: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    raw_objects = merge_raw_objects(raw_objects, domain)
    inferred_domain_sid = infer_domain_sid(raw_objects, domain)

    converted: Dict[str, List[Dict[str, Any]]] = {
        "domains": [],
        "computers": [],
        "users": [],
        "groups": [],
        "ous": [],
        "gpos": [],
        "containers": [],
    }

    raw_by_oid: Dict[str, Dict[str, Any]] = {}

    for raw in raw_objects:
        data_type = classify_object(raw)
        obj = None

        if data_type == "domains":
            obj = make_domain(raw, domain, all_properties)
        elif data_type == "users":
            obj = make_user(raw, domain, inferred_domain_sid, all_properties)
        elif data_type == "computers":
            obj = make_computer(raw, domain, inferred_domain_sid, all_properties)
        elif data_type == "groups":
            obj = make_group(raw, domain, inferred_domain_sid, all_properties)
        elif data_type == "ous":
            obj = make_ou(raw, domain, inferred_domain_sid, all_properties)
        elif data_type == "gpos":
            obj = make_gpo(raw, domain, all_properties)
        elif data_type == "containers":
            obj = make_container(raw, domain, inferred_domain_sid, all_properties)
        elif data_type in {"schemas", "trusts", "trustaccounts"}:
            continue
        else:
            dn = first(get_attr(raw, "distinguishedName"), "<unknown DN>")
            print(f"[!] Skipping unsupported object: {dn}")

        if obj:
            converted[data_type].append(obj)
            raw_by_oid[str(obj["ObjectIdentifier"]).upper()] = raw

    if not converted["domains"]:
        synthetic = make_synthetic_domain(domain, base_dn, inferred_domain_sid)
        if synthetic:
            converted["domains"].append(synthetic)

    resolve_domain_trusts(converted, raw_objects)

    if default_principals:
        add_default_principals(converted)

    resolve_group_members(converted, raw_objects, domain)
    resolve_ou_members(converted)
    link_gpos(converted, raw_by_oid, domain)
    resolve_delegation_targets(converted)

    if parse_acls:
        parse_acl_edges(converted, raw_by_oid, build_schema_guid_map(raw_objects), domain)

    return converted


def wrap_bh_json(
    data_type: str,
    objects: List[Dict[str, Any]],
    bh_version: int,
    collection_methods: int = DEFAULT_COLLECTION_METHODS,
) -> Dict[str, Any]:
    return {
        "data": objects,
        "meta": {
            "type": data_type,
            "count": len(objects),
            "methods": collection_methods,
            "version": bh_version,
            "collectorversion": COLLECTOR_VERSION,
        },
    }


def normalize_zip_path(path: str) -> str:
    if path.lower().endswith(".zip"):
        return path
    return f"{path}.zip"


def find_json_member(archive: zipfile.ZipFile, data_type: str) -> Optional[str]:
    exact = f"{data_type}.json"
    names = archive.namelist()
    if exact in names:
        return exact

    prefix = f"{data_type}_"
    candidates = [
        name for name in names
        if os.path.basename(name).startswith(prefix) and name.lower().endswith(".json")
    ]
    return sorted(candidates)[-1] if candidates else None


def read_existing_bh_objects_from_zip(zip_path: str, data_type: str) -> List[Dict[str, Any]]:
    if not os.path.exists(zip_path):
        return []

    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            member_name = find_json_member(archive, data_type)
            if not member_name:
                return []

            with archive.open(member_name, "r") as f:
                existing = json.loads(f.read().decode("utf-8"))

        data = existing.get("data", [])
        return data if isinstance(data, list) else []

    except zipfile.BadZipFile:
        print(f"[!] Existing file is not a valid ZIP archive: {zip_path}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Failed to read {data_type} from {zip_path}: {e}", file=sys.stderr)
        return []


def merge_bh_objects(old_objects: List[Dict[str, Any]], new_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for obj in old_objects:
        oid = obj.get("ObjectIdentifier")
        if oid:
            merged[str(oid).upper()] = obj

    for obj in new_objects:
        oid = obj.get("ObjectIdentifier")
        if oid:
            merged[str(oid).upper()] = obj

    return list(merged.values())


def build_zip_payload(
    zip_path: str,
    converted: Dict[str, List[Dict[str, Any]]],
    selected_types: List[str],
    merge: bool = False,
    write_empty: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    payload: Dict[str, List[Dict[str, Any]]] = {}

    if merge and os.path.exists(zip_path):
        for data_type in SUPPORTED_TYPES:
            existing_objects = read_existing_bh_objects_from_zip(zip_path, data_type)
            if existing_objects:
                payload[data_type] = existing_objects

    for data_type in selected_types:
        new_objects = converted.get(data_type, [])

        if merge:
            old_objects = payload.get(data_type, [])
            final_objects = merge_bh_objects(old_objects, new_objects)
        else:
            final_objects = new_objects

        if final_objects or write_empty:
            payload[data_type] = final_objects
        else:
            payload.pop(data_type, None)
            print(f"[+] Skipped empty {data_type}")

    return payload


def write_bh_zip(
    zip_path: str,
    payload: Dict[str, List[Dict[str, Any]]],
    bh_version: int,
    timestamped_names: bool = False,
    collection_methods: int = DEFAULT_COLLECTION_METHODS,
) -> str:
    ensure_parent_dir(zip_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for data_type in SUPPORTED_TYPES:
            if data_type not in payload:
                continue

            objects = payload[data_type]
            member_name = f"{data_type}_{timestamp}.json" if timestamped_names else f"{data_type}.json"
            body = json.dumps(
                wrap_bh_json(data_type, objects, bh_version, collection_methods=collection_methods),
                indent=2,
                ensure_ascii=False,
            )
            archive.writestr(member_name, body)
            print(f"[+] Wrote {len(objects)} {data_type} -> {zip_path}:{member_name}")

    return zip_path


def build_server(args: argparse.Namespace) -> Any:
    require_ldap3()
    use_ssl = bool(args.ldaps)
    port = args.port or (636 if use_ssl else 389)
    tls_config = None

    if use_ssl:
        validate = ssl.CERT_REQUIRED if args.validate_cert else ssl.CERT_NONE
        tls_config = Tls(validate=validate, version=ssl.PROTOCOL_TLS_CLIENT)

    return Server(
        args.dc_ip,
        port=port,
        use_ssl=use_ssl,
        get_info=ALL,
        tls=tls_config,
        connect_timeout=args.timeout,
    )


def discover_rootdse(args: argparse.Namespace) -> Dict[str, Optional[str]]:
    require_ldap3()
    server = build_server(args)

    conn = None
    try:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True, receive_timeout=args.timeout, check_names=False)
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[
                "defaultNamingContext",
                "rootDomainNamingContext",
                "dnsHostName",
                "configurationNamingContext",
                "schemaNamingContext",
            ],
        )

        if not conn.entries:
            return {}

        entry = conn.entries[0]
        data = entry.entry_attributes_as_dict
        base_dn = first(data.get("defaultNamingContext"))
        root_dn = first(data.get("rootDomainNamingContext"))
        dns_host = first(data.get("dnsHostName"))
        config_dn = first(data.get("configurationNamingContext"))
        schema_dn = first(data.get("schemaNamingContext"))
        domain = normalize_domain(None, base_dn) if base_dn else None

        return {
            "base_dn": base_dn,
            "root_dn": root_dn,
            "dns_host": dns_host,
            "config_dn": config_dn,
            "schema_dn": schema_dn,
            "domain": domain,
        }

    except LDAPException as e:
        print(f"[-] RootDSE discovery failed: {e}", file=sys.stderr)
        return {}

    finally:
        if conn:
            try:
                conn.unbind()
            except Exception:
                pass


def connect_ldap(args: argparse.Namespace) -> Any:
    require_ldap3()
    server = build_server(args)

    try:
        if args.anonymous:
            print("[+] Using anonymous LDAP bind")
            return Connection(server, authentication=ANONYMOUS, auto_bind=True, receive_timeout=args.timeout, check_names=False)

        if not args.user or not args.password:
            print("[-] --user and --password are required unless --anonymous is used", file=sys.stderr)
            sys.exit(1)

        if "\\" in args.user:
            auth = NTLM
            print("[+] Using NTLM authentication")
        else:
            auth = SIMPLE
            print("[+] Using SIMPLE authentication")

        return Connection(server, user=args.user, password=args.password, authentication=auth, auto_bind=True, receive_timeout=args.timeout, check_names=False)

    except LDAPException as e:
        print(f"[-] LDAP bind failed: {e}", file=sys.stderr)
        sys.exit(1)


def build_attribute_list(args: argparse.Namespace) -> List[str]:
    attributes = [
        "objectSid",
        "objectGUID",
        "objectClass",
        "distinguishedName",
        "sAMAccountName",
        "sAMAccountType",
        "cn",
        "name",
        "ou",
        "displayName",
        "description",
        "mail",
        "title",
        "department",
        "member",
        "memberOf",
        "servicePrincipalName",
        "userAccountControl",
        "adminCount",
        "whenCreated",
        "lastLogon",
        "lastLogonTimestamp",
        "pwdLastSet",
        "operatingSystem",
        "operatingSystemServicePack",
        "dNSHostName",
        "primaryGroupID",
        "sIDHistory",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-GroupMSAMembership",
        "gPLink",
        "gPOptions",
        "gPCFileSysPath",
        "msDS-Behavior-Version",
        "trustPartner",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "isDeleted",
    ]

    if args.collect_laps:
        attributes.extend(OPTIONAL_LAPS_ATTRIBUTES)

    if args.acl or args.collect_acls or args.parse_acls:
        attributes.extend(OPTIONAL_ACL_ATTRIBUTES)

    return list(dict.fromkeys(attributes))


def schema_attribute_list(args: argparse.Namespace) -> List[str]:
    return ["name", "lDAPDisplayName", "schemaIDGUID"]


def bofhound_filter() -> str:
    return (
        "(|"
        "(objectClass=domainDNS)"
        "(sAMAccountType=268435456)"
        "(sAMAccountType=268435457)"
        "(sAMAccountType=536870912)"
        "(sAMAccountType=536870913)"
        "(sAMAccountType=805306368)"
        "(sAMAccountType=805306369)"
        "(objectClass=organizationalUnit)"
        "(objectClass=groupPolicyContainer)"
        "(objectClass=trustedDomain)"
        ")"
    )


def build_search_plan(args: argparse.Namespace, discovered: Dict[str, Optional[str]]) -> List[SearchSpec]:
    attributes = build_attribute_list(args)
    plan: List[SearchSpec] = []

    use_preset = args.bofhound or not args.ldapquery
    if use_preset:
        plan.append(SearchSpec("bofhound-main", args.base_dn, bofhound_filter(), SUBTREE, attributes))

        schema_dn = discovered.get("schema_dn")
        if not args.skip_schema and schema_dn:
            plan.append(SearchSpec("schema-guid-map", schema_dn, "(schemaIDGUID=*)", SUBTREE, schema_attribute_list(args)))
    else:
        plan.append(SearchSpec("custom", args.base_dn, args.ldapquery, SUBTREE, attributes))

        schema_dn = discovered.get("schema_dn")
        if args.collect_schema and schema_dn:
            plan.append(SearchSpec("schema-guid-map", schema_dn, "(schemaIDGUID=*)", SUBTREE, schema_attribute_list(args)))

    return plan


def retryable_without_optional_attrs(spec: SearchSpec) -> Optional[SearchSpec]:
    optional = {attr.lower() for attr in OPTIONAL_LAPS_ATTRIBUTES + OPTIONAL_ACL_ATTRIBUTES}
    attributes = [attr for attr in spec.attributes if attr.lower() not in optional]

    if len(attributes) == len(spec.attributes):
        return None

    return SearchSpec(f"{spec.name}-without-optional-attrs", spec.search_base, spec.search_filter, spec.search_scope, attributes)


def collect_entries_for_spec(conn: Any, args: argparse.Namespace, spec: SearchSpec, retry: bool = True) -> List[Dict[str, Any]]:
    print(f"[+] LDAP query [{spec.name}] base: {spec.search_base}")
    print(f"[+] LDAP query [{spec.name}] filter: {spec.search_filter}")
    print(f"[+] LDAP query [{spec.name}] attributes: {len(spec.attributes)}")

    entries: List[Dict[str, Any]] = []

    try:
        paged_cookie = None

        while True:
            conn.search(
                search_base=spec.search_base,
                search_filter=spec.search_filter,
                search_scope=spec.search_scope,
                attributes=spec.attributes,
                paged_size=args.page_size,
                paged_cookie=paged_cookie,
            )

            result_code = conn.result.get("result")
            if result_code not in (0, 4):
                if retry:
                    retry_spec = retryable_without_optional_attrs(spec)
                    if retry_spec:
                        print(f"[!] LDAP result for {spec.name}: {conn.result}", file=sys.stderr)
                        print("[!] Retrying without optional LAPS/ACL attributes.", file=sys.stderr)
                        return collect_entries_for_spec(conn, args, retry_spec, retry=False)

                print(f"[-] LDAP result for {spec.name}: {conn.result}", file=sys.stderr)
                sys.exit(1)

            entries.extend(entry_to_raw_object(entry) for entry in conn.entries)

            controls = conn.result.get("controls", {})
            paged_control = controls.get("1.2.840.113556.1.4.319", {})
            value = paged_control.get("value", {})
            paged_cookie = value.get("cookie")

            if not paged_cookie:
                break

    except LDAPException as e:
        if retry:
            retry_spec = retryable_without_optional_attrs(spec)
            if retry_spec:
                print(f"[!] LDAP search failed for {spec.name}: {e}", file=sys.stderr)
                print("[!] Retrying without optional LAPS/ACL attributes.", file=sys.stderr)
                return collect_entries_for_spec(conn, args, retry_spec, retry=False)

        print(f"[-] LDAP search failed for {spec.name}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] LDAP entries received [{spec.name}]: {len(entries)}")
    return entries


def collect_entries(conn: Any, args: argparse.Namespace, plan: Sequence[SearchSpec]) -> List[Dict[str, Any]]:
    all_entries: List[Dict[str, Any]] = []

    for spec in plan:
        all_entries.extend(collect_entries_for_spec(conn, args, spec))

    print(f"[+] LDAP entries received total: {len(all_entries)}")
    return all_entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BOFHound-style BloodHound JSON collector using live LDAP queries")

    parser.add_argument(
        "ldapquery",
        nargs="?",
        help="Optional custom LDAP filter. If omitted, OPSECHound runs a BOFHound-style multi-object collection preset.",
    )

    parser.add_argument("--user", help='LDAP username, e.g. "EXAMPLE\\user" or "user@example.local"')
    parser.add_argument("--password", help="LDAP password")
    parser.add_argument("--anonymous", action="store_true", help="Use anonymous LDAP bind")
    parser.add_argument("--discover", action="store_true", help="Discover base DN, schema DN, and domain from LDAP RootDSE")

    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP or hostname")
    parser.add_argument("--base-dn", help='LDAP base DN, e.g. "DC=example,DC=local"')
    parser.add_argument("--domain", help='AD domain, e.g. "EXAMPLE.LOCAL"')

    parser.add_argument("--ldaps", action="store_true", help="Use LDAPS")
    parser.add_argument("--validate-cert", action="store_true", help="Validate LDAPS certificate")
    parser.add_argument("--port", type=int, help="LDAP/LDAPS port")

    parser.add_argument("--timeout", type=int, default=15, help="LDAP timeout in seconds")
    parser.add_argument("--page-size", type=int, default=500, help="LDAP paged search size")
    parser.add_argument("--out", default="./bloodhound_bofhound.zip", help="Output ZIP path. If .zip is omitted, it will be added automatically.")

    parser.add_argument("--bofhound", action="store_true", help="Run the BOFHound-style collection preset even if a custom LDAP filter is supplied.")
    parser.add_argument("--types", nargs="+", choices=SUPPORTED_TYPES, help="Only write selected BloodHound object types.")
    parser.add_argument("--merge", action="store_true", help="Merge with existing JSON files inside --out ZIP instead of replacing them.")
    parser.add_argument("--write-empty", action="store_true", help="Write empty JSON members too. By default empty object types are skipped.")
    parser.add_argument("--timestamped-names", action="store_true", help="Name ZIP members like BOFHound does, e.g. users_YYYYMMDD_HHMMSS.json.")
    parser.add_argument("--bh-version", type=int, default=BH_VERSION, help="BloodHound JSON meta version. Default follows current SharpHound-style output.")
    parser.add_argument("--all-properties", action="store_true", help="Include all LDAP properties collected except raw security descriptors and schema-only fields.")
    parser.add_argument("--collect-laps", action="store_true", help="Try to collect classic and Windows LAPS expiration attributes.")
    parser.add_argument("--acl", action="store_true", help="Collect and parse nTSecurityDescriptor into BloodHound Aces. Requires: pip3 install bloodhound.")
    parser.add_argument("--collect-acls", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parse-acls", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--skip-schema", action="store_true", help="Do not run the schemaIDGUID query in BOFHound preset mode.")
    parser.add_argument("--collect-schema", action="store_true", help="Also collect schemaIDGUID map when running a custom LDAP filter.")
    parser.add_argument("--no-default-principals", action="store_true", help="Do not add BOFHound-style default well-known users/groups.")

    args = parser.parse_args()

    if args.acl or args.collect_acls or args.parse_acls:
        args.acl = True
        args.collect_acls = True
        args.parse_acls = True

    return args


def main() -> None:
    args = parse_args()
    args.out = normalize_zip_path(args.out)

    discovered: Dict[str, Optional[str]] = {}
    preset_mode = args.bofhound or not args.ldapquery
    needs_schema_dn = (preset_mode and not args.skip_schema) or (not preset_mode and args.collect_schema)
    should_discover = args.discover or not args.base_dn or not args.domain or needs_schema_dn
    if should_discover:
        discovered = discover_rootdse(args)

        if discovered:
            print("[+] RootDSE discovery:")
            print(f"    dnsHostName: {discovered.get('dns_host')}")
            print(f"    defaultNamingContext: {discovered.get('base_dn')}")
            print(f"    rootDomainNamingContext: {discovered.get('root_dn')}")
            print(f"    configurationNamingContext: {discovered.get('config_dn')}")
            print(f"    schemaNamingContext: {discovered.get('schema_dn')}")
            print(f"    domain: {discovered.get('domain')}")

            if not args.base_dn and discovered.get("base_dn"):
                args.base_dn = discovered["base_dn"]

            if not args.domain and discovered.get("domain"):
                args.domain = discovered["domain"]

    if not args.base_dn:
        print("[-] --base-dn is required if discovery fails", file=sys.stderr)
        sys.exit(1)

    domain = normalize_domain(args.domain, args.base_dn)
    if args.acl and not (args.bofhound or not args.ldapquery):
        args.collect_schema = True

    plan = build_search_plan(args, discovered)

    conn = connect_ldap(args)

    try:
        raw_entries = collect_entries(conn, args, plan)
        converted = convert(
            raw_entries,
            domain,
            args.base_dn,
            all_properties=args.all_properties,
            default_principals=not args.no_default_principals,
            parse_acls=args.parse_acls,
        )

        selected_types = args.types or BOFHOUND_OUTPUT_TYPES
        payload = build_zip_payload(args.out, converted, selected_types, merge=args.merge, write_empty=args.write_empty)
        collection_methods = DEFAULT_COLLECTION_METHODS | (COLLECTION_METHOD_ACL if args.acl else 0)
        archive_path = write_bh_zip(
            args.out,
            payload,
            bh_version=args.bh_version,
            timestamped_names=args.timestamped_names,
            collection_methods=collection_methods,
        )

        print("[+] Done.")
        print(f"[+] BloodHound archive: {archive_path}")
        print("[!] OPSEC note: only LDAP data requested by this tool is represented.")
        print("[!] Sessions, local admins, user rights, registry sessions, and live host collection are not implemented.")

    finally:
        try:
            conn.unbind()
        except Exception:
            pass


if __name__ == "__main__":
    main()

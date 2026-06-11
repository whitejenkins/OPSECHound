# OPSECHound

OPSECHound is a BOFHound-style BloodHound JSON collector that runs LDAP queries itself instead of parsing ldapsearch logs.

```bash
pip3 install ldap3

python3 OPSECHound.py "(objectClass=user)" \
  --dc-ip 192.168.56.10 \
  --base-dn "DC=example,DC=local" \
  --domain "EXAMPLE.LOCAL" \
  --user "EXAMPLE\\user" \
  --password "Password123!" \
  --out ./bloodhound_bofhound.zip
```

If no LDAP filter is supplied, the tool runs the BOFHound-style preset for domains, users, computers, groups, OUs, GPOs, trusts, and schema GUIDs. You can still supply a custom filter and limit output with `--types`.

Useful flags:

- `--bofhound` - force the preset even when a custom filter is supplied
- `--types users groups computers` - write only selected BloodHound object files
- `--merge` - merge into an existing output ZIP
- `--timestamped-names` - write member names like `users_YYYYMMDD_HHMMSS.json`
- `--collect-laps` - request LAPS expiration attributes
- `--acl` - request and parse ACLs, requires `pip3 install bloodhound`

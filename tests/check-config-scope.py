#!/usr/bin/env python3
"""
Validate that [scope:] annotations in doc/sample.config are consistent
with the actual config parsing code in src/config.c and src/sup-config/file.c.

Scope vocabulary:
  global (non-reloadable)  -- perm_cfg_st; requires restart; cannot differ per vhost
  vhost (non-reloadable)   -- perm_cfg_st; requires restart; can differ per vhost
  global                   -- cfg_st; reloadable; cannot be set in [vhost:] sections
  vhost                    -- cfg_st; reloadable; can differ per vhost
  vhost user               -- cfg_st; reloadable; per-vhost AND per-user/group overridable

Checks performed:
  (a) Every option in sample.config has a [scope: ...] annotation.
  (b) Every option annotated [... global] has an error_on_vhost() call in
      config.c (or is a permanent-global option in perm_cfg_st, which never
      reaches error_on_vhost).
  (c) Every error_on_vhost() option in config.c is annotated [... global] in
      sample.config.
  (d) Every option annotated [...user...] is handled in src/sup-config/file.c.
  (e) Every option in src/sup-config/file.c is annotated [...user...] in
      sample.config.
  (f) Every option in sample.config annotated [...user...] is also annotated
      [...vhost...] (user-overridable options must also be settable per-vhost).
  (g) Every field in struct cfg_st and struct perm_cfg_st in src/vpn.h has a
      [scope: ...] inline comment.

Exit code: 0 on success, 1 if any errors are found.
"""

import re
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)

SAMPLE_CONFIG = os.path.join(ROOT, "doc", "sample.config")
CONFIG_C = os.path.join(ROOT, "src", "config.c")
SUP_CONFIG_FILE = os.path.join(ROOT, "src", "sup-config", "file.c")
VPN_H = os.path.join(ROOT, "src", "vpn.h")


def read_file(path):
    with open(path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Step 1: Parse doc/sample.config
# Returns dict: {option_name: scope_string or None}
# ---------------------------------------------------------------------------
def extract_sample_config_scopes(text):
    """
    For each option line (has '=' and is not a pure comment/blank),
    look backwards for the nearest '# [scope: ...]' line.
    """
    lines = text.splitlines()
    scopes = {}

    for i, line in enumerate(lines):
        # Strip leading '#' and whitespace to get the raw content
        stripped = line.lstrip()
        if stripped.startswith("#"):
            after_hash = stripped[1:]
            # Only treat as a potential option if 0 or 1 spaces follow '#'.
            # Two or more spaces indicate an example buried inside a prose
            # comment block (e.g. "#  CN = 2.5.4.3" or "#     kdc = ...").
            if after_hash.startswith("  "):
                continue
            stripped = after_hash.lstrip()

        # Is it an option line? Must contain ' = ' or '= ' and not be empty
        if "=" not in stripped or stripped.startswith("["):
            continue
        # Skip pure comment lines (the line itself starts with '#' then a word)
        raw = line.lstrip()
        if raw == "" or raw.startswith("###"):
            continue
        # Extract option name: everything before the first '='
        eq_pos = stripped.find("=")
        opt = stripped[:eq_pos].strip()
        # Reject options that look like key=value inside a comment or contain spaces badly
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', opt):
            continue

        # Avoid duplicates — keep first occurrence (the active/commented-first)
        if opt in scopes:
            continue

        # Walk backwards looking for a '# [scope: ...]' tag
        scope = None
        for j in range(i - 1, max(i - 10, -1), -1):
            prev = lines[j].strip()
            m = re.match(r'^#\s*\[scope:\s*([^\]]+)\]', prev)
            if m:
                scope = m.group(1).strip()
                break
            # Stop if we hit a blank line or a non-comment line
            if prev == "" or (prev and not prev.startswith("#")):
                break

        scopes[opt] = scope

    return scopes


# ---------------------------------------------------------------------------
# Step 2: Parse src/config.c — options that call error_on_vhost()
# ---------------------------------------------------------------------------
def extract_error_on_vhost_options(text):
    """Return set of option names passed to error_on_vhost()."""
    # Pattern: error_on_vhost(vhost->name, "option-name")
    pattern = re.compile(r'error_on_vhost\s*\([^,]+,\s*"([^"]+)"')
    return set(pattern.findall(text))


# ---------------------------------------------------------------------------
# Step 3: Parse src/sup-config/file.c — options handled per-user/group
# ---------------------------------------------------------------------------
def extract_sup_config_options(text):
    """Return set of option names handled in the per-user/group file parser."""
    pattern = re.compile(r'strcmp\s*\(\s*name\s*,\s*"([^"]+)"')
    return set(pattern.findall(text))


# ---------------------------------------------------------------------------
# Step 4: Parse src/vpn.h — check that cfg_st and perm_cfg_st fields
#         all have [scope: ...] annotations.
# ---------------------------------------------------------------------------
def check_vpn_h_annotations(text):
    """
    Returns list of field declarations in cfg_st and perm_cfg_st
    that are missing a [scope: ...] inline comment.
    """
    missing = []

    # Find cfg_st body
    for struct_name in ("struct cfg_st", "struct perm_cfg_st"):
        m = re.search(re.escape(struct_name) + r'\s*\{', text)
        if not m:
            continue
        start = m.end()
        # Find matching closing brace
        depth = 1
        pos = start
        while pos < len(text) and depth > 0:
            if text[pos] == '{':
                depth += 1
            elif text[pos] == '}':
                depth -= 1
            pos += 1
        body = text[start:pos - 1]

        # Find field declarations: lines ending in ';' that look like declarations
        for line in body.splitlines():
            stripped = line.strip()
            # Skip blank, comment-only, preprocessor, and struct/union lines
            if (not stripped or stripped.startswith("/*") or stripped.startswith("//")
                    or stripped.startswith("#") or stripped.startswith("}")
                    or stripped.startswith("{") or stripped.startswith("struct ")
                    or stripped.startswith("typedef ")):
                continue
            # Must end with ';'
            if not stripped.endswith(";"):
                continue
            # Skip lines that are closing braces with semicolons e.g. '} name;'
            if stripped.startswith("}"):
                continue
            # Check for [scope: ...] annotation
            if "[scope:" not in line:
                # Extract a clean field name for reporting
                # Remove array/pointer noise
                name_m = re.search(r'\b(\w+)\s*(?:\[[^\]]*\])?\s*;', stripped)
                field = name_m.group(1) if name_m else stripped[:40]
                missing.append(f"  {struct_name}: field '{field}' has no [scope:] annotation")

    return missing


# ---------------------------------------------------------------------------
# Main validation
# ---------------------------------------------------------------------------
def main():
    errors = []

    sample_text = read_file(SAMPLE_CONFIG)
    config_c_text = read_file(CONFIG_C)
    sup_config_text = read_file(SUP_CONFIG_FILE)
    vpn_h_text = read_file(VPN_H)

    # Parse
    sample_scopes = extract_sample_config_scopes(sample_text)
    global_in_code = extract_error_on_vhost_options(config_c_text)
    user_in_code = extract_sup_config_options(sup_config_text)

    # Non-reloadable options live in perm_cfg_st and never go through
    # error_on_vhost(); they are enforced structurally.  Collect from sample.config.
    perm_global_opts = {
        opt for opt, scope in sample_scopes.items()
        if scope and "non-reloadable" in scope
    }

    # (a) All options in sample.config have a scope annotation
    for opt, scope in sorted(sample_scopes.items()):
        if scope is None:
            errors.append(
                f"sample.config: '{opt}' has no [scope:] annotation"
            )

    # (b) [global] options (reloadable only) must have error_on_vhost in config.c;
    #     [global (non-reloadable)] options live in perm_cfg_st and are exempt.
    for opt, scope in sorted(sample_scopes.items()):
        if scope and "global" in scope and "non-reloadable" not in scope:
            if opt not in global_in_code:
                errors.append(
                    f"sample.config: '{opt}' is annotated [{scope}] but "
                    f"has no error_on_vhost() call in config.c"
                )

    # (c) Every error_on_vhost option must be annotated [... global] in sample.config
    for opt in sorted(global_in_code):
        scope = sample_scopes.get(opt)
        if scope is None:
            errors.append(
                f"config.c: error_on_vhost('{opt}') but option is missing "
                f"from sample.config annotations"
            )
        elif "global" not in scope:
            errors.append(
                f"config.c: error_on_vhost('{opt}') but sample.config "
                f"annotates it [{scope}] (expected '... global')"
            )

    # (d) [...user...] options must be in sup-config/file.c
    for opt, scope in sorted(sample_scopes.items()):
        if scope and "user" in scope:
            if opt not in user_in_code:
                errors.append(
                    f"sample.config: '{opt}' is annotated [{scope}] but is not "
                    f"handled in src/sup-config/file.c"
                )

    # (e) Every option in sup-config/file.c must be annotated [...user...] in sample.config
    # Some options (like 'iroute', 'hostname', 'explicit-ipv4', 'explicit-ipv6')
    # are per-user only and don't appear in the global sample.config — skip those.
    PER_USER_ONLY = {
        "iroute", "hostname", "explicit-ipv4", "explicit-ipv6",
        "ipv4-dns", "ipv6-dns", "ipv4-nbns", "ipv6-nbns",
    }
    for opt in sorted(user_in_code):
        if opt in PER_USER_ONLY:
            continue
        scope = sample_scopes.get(opt)
        if scope is None:
            errors.append(
                f"sup-config/file.c: handles '{opt}' but option is missing "
                f"from sample.config annotations"
            )
        elif "user" not in scope:
            errors.append(
                f"sup-config/file.c: handles '{opt}' but sample.config "
                f"annotates it [{scope}] (expected '... user ...')"
            )

    # (f) Every [...user...] option in sample.config must also be [...vhost...]
    for opt, scope in sorted(sample_scopes.items()):
        if scope and "user" in scope and "vhost" not in scope:
            errors.append(
                f"sample.config: '{opt}' is annotated [{scope}] but "
                f"user-overridable options must also be settable per-vhost "
                f"(expected '[scope: vhost user]')"
            )

    # (g) vpn.h struct field annotations
    missing_annot = check_vpn_h_annotations(vpn_h_text)
    if missing_annot:
        errors.append(
            "src/vpn.h: the following fields are missing [scope:] annotations:"
        )
        errors.extend(missing_annot)

    # Report
    if errors:
        print("config-scope-check: FAILED")
        for e in errors:
            print(f"  ERROR: {e}")
        return 1

    print(f"config-scope-check: OK ({len(sample_scopes)} options checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

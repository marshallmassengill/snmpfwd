#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Shared filesystem-path macro-expansion helper.

Used by the bundled `logger` plugin to resolve ${macro} tokens in a log
file destination template (e.g. /var/log/snmpfwd/${snmp-peer-id}.log).
Extracted here so the sanitization and missing-macro behavior can be
unit-tested without exec()-ing the plugin module."""
from __future__ import annotations

import re
from typing import Iterable, Mapping, Tuple


# Characters that are either illegal in filesystem paths (NUL, backslash
# on POSIX, colon on Windows) or create ambiguous path components when
# they land inside a macro expansion — e.g. snmp-peer-address renders as
# "127.0.0.1:1161" and a raw ":" in a destination template would split
# the filename on Windows.
_PATH_SANITIZE = str.maketrans({
    '/': '_',
    '\\': '_',
    ':': '_',
    '\x00': '_',
    ' ': '_',
})


_MACRO_RE = re.compile(r'\$\{([^}]+)\}')


def format_path(template: str, context: Mapping[str, object]) -> Tuple[str, list]:
    """Expand ${...} macros in `template` from `context`.

    Returns `(resolved_path, missing_macros)`:
    - `resolved_path`: the template with every ${key} replaced by the
      sanitized `str(context[key])`. Unresolved tokens become the literal
      string `_unknown` so the returned path stays a valid filename.
    - `missing_macros`: sorted list of the ${...} tokens that had no entry
      in `context`. Callers typically log a warning on those — but only
      once per token, which is the caller's responsibility (this helper
      is pure and stateless).

    Values are passed through `str()` and then a sanitizer that maps
    path-separator and ambiguous characters (`/`, `\\`, `:`, NUL, space)
    to `_` so no macro expansion can split a path component."""
    resolved = template
    for key, value in context.items():
        token = '${%s}' % key
        if token in resolved:
            resolved = resolved.replace(
                token, str(value).translate(_PATH_SANITIZE)
            )

    missing = sorted({m.group(0) for m in _MACRO_RE.finditer(resolved)})
    if missing:
        for tok in missing:
            resolved = resolved.replace(tok, '_unknown')
    return resolved, missing

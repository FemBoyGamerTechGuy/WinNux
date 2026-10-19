#!/usr/bin/env python3
"""gen_sigs32.py — generate src/dlls/gen_sigs32.c (32-bit call metadata).

Parses each src/dlls/*.c:
  1. WN_API function DEFINITIONS  -> symbol -> (stack words, doubles, vararg)
  2. EXPORT TABLE entries {"Name", symbol} -> export name -> symbol
Joins them and emits a lookup table keyed by EXPORT NAME (Win32 export
names are globally unique across our builtin tables; aliases share rows).

32-bit word counting: every by-value parameter is one 4-byte stack word
(zero-extended into the 64-bit register), EXCEPT by-value double/float
(two words, delivered via the XMM bank). "..." marks vararg (always cdecl).
Unknown functions fall back to a 4-word stdcall guess at runtime.
"""
import re
import sys
import glob
import os

SRC_DIRS = ["src/dlls"]
OUT = "src/dlls/gen_sigs32.c"

DEF_RE = re.compile(
    r"WN_API[ \t]+[A-Za-z_][A-Za-z0-9_ \t\*]*?[ \t\*]"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")
EXPORT_RE = re.compile(
    r'\{\s*"([A-Za-z0-9_#@$.]+)"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}')


def extract_args(src, open_paren_end):
    """Paren-depth scan from just after '('. Returns the arg string or
    None when the body does not start with '{' (prototype = not a def)."""
    depth = 1
    i = open_paren_end
    n = len(src)
    while i < n and depth:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    if depth:
        return None
    args = src[open_paren_end:i - 1]
    # skip whitespace / attributes to the body
    j = i
    while j < n and (src[j] in " \t\r\n\\"):
        j += 1
    if j >= n or src[j] != "{":
        return None       # prototype (ends with ;) — not a definition
    return args


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def parse_params(argstr):
    argstr = argstr.strip()
    # normalize whitespace (definitions can span lines)
    argstr = re.sub(r"\s+", " ", argstr)
    if argstr in ("", "void"):
        return []
    parts, depth, cur = [], 0, ""
    for ch in argstr:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def classify(p):
    """-> (is_double, is_vararg, suspect)"""
    p = p.strip()
    if p == "...":
        return False, True, False
    tokens = p.replace("*", " * ").split()
    if not tokens:
        return False, False, True
    keywords = ("double", "float", "int", "long", "short", "char",
                "unsigned", "signed", "void", "const", "struct")
    type_toks = tokens
    if len(tokens) > 1 and \
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[-1]) and \
            "*" not in tokens[-1] and tokens[-1] not in keywords:
        type_toks = tokens[:-1]
    t = " ".join(type_toks)
    if "*" in t:
        return False, False, False
    if re.search(r"\b(double|float)\b", t):
        return True, False, False
    if re.search(r"\b(int64_t|uint64_t|long\s+long|LONGLONG)\b", t):
        return False, False, True
    return False, False, False


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    os.chdir(root)
    sigs = {}          # symbol -> (words, nd, vararg)
    exports = {}       # export name -> symbol
    warn = []
    for d in SRC_DIRS:
        for path in sorted(glob.glob(d + "/*.c")):
            if path.endswith("gen_sigs32.c"):
                continue
            src = strip_comments(open(path, encoding="utf-8",
                                      errors="replace").read())
            for m in DEF_RE.finditer(src):
                name = m.group("name")
                args = extract_args(src, m.end())
                if args is None:
                    continue
                params = parse_params(args)
                words = 0
                nd = 0
                vararg = False
                suspect = False
                for p in params:
                    is_d, is_v, is_s = classify(p)
                    if is_v:
                        vararg = True
                        continue
                    words += 2 if is_d else 1
                    if is_d:
                        nd += 1
                    if is_s:
                        suspect = True
                sigs[name] = (words, nd, vararg)
                if suspect:
                    warn.append("suspect param: %s (%s)" % (name, path))
                if words > 12:
                    warn.append("arity>12 words: %s (%s)" % (name, path))
            for m in EXPORT_RE.finditer(src):
                exp, sym = m.group(1), m.group(2)
                if exp in exports and exports[exp] != sym:
                    warn.append("export name reused: %s (%s vs %s)" %
                                (exp, exports[exp], sym))
                exports[exp] = sym

    n = 0
    lines = []
    lines.append("/* GENERATED by scripts/dev/gen_sigs32.py — do not edit.")
    lines.append(" * 32-bit call metadata for the wow64 thunk dispatcher:")
    lines.append(" * stack words (4 bytes each), by-value doubles (XMM),")
    lines.append(" * vararg flag. Keyed by export name; unknown -> runtime")
    lines.append(" * 4-word stdcall guess. */")
    lines.append("#include \"wn_wow64.h\"")
    lines.append("#include <string.h>")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    const char *name;")
    lines.append("    uint16_t   words;")
    lines.append("    uint8_t    nd;")
    lines.append("    uint8_t    vararg;")
    lines.append("} sig32_ent;")
    lines.append("")
    lines.append("static const sig32_ent sigs[] = {")
    for exp in sorted(exports):
        sym = exports[exp]
        if sym not in sigs:
            continue           # data export or non-WN_API: not thunkable here
        words, nd, vararg = sigs[sym]
        lines.append('    { "%s", %d, %d, %d },' % (exp, words, nd, vararg))
        n += 1
    lines.append("    { 0, 0, 0, 0 },")
    lines.append("};")
    lines.append("")
    lines.append("int wn_sig32_lookup(const char *name, wn_sig32 *out)")
    lines.append("{")
    lines.append("    for (const sig32_ent *e = sigs; e->name; e++) {")
    lines.append("        if (strcmp(e->name, name) == 0) {")
    lines.append("            memset(out, 0, sizeof *out);")
    lines.append("            out->arity = e->words;")
    lines.append("            out->n_double = e->nd;")
    lines.append("            out->cleanup = e->vararg ? 0 : e->words;")
    lines.append("            out->flags = e->vararg ? WN32_VARARG : 0;")
    lines.append("            return 1;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    open(OUT, "w").write("\n".join(lines))
    for w in warn:
        print("WARN:", w, file=sys.stderr)
    print("generated %s: %d exports" % (OUT, n))


if __name__ == "__main__":
    main()

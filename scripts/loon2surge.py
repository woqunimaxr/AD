#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
loon2surge.py — Loon .plugin -> Surge .sgmodule

源:  https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/plugin/blockAds.plugin
出:  surge/blockAds.sgmodule

映射要点
--------
[Argument]   ->  #!arguments=名字:默认值  +  脚本行 argument="{\\"k\\":{{{k}}}}}"
[Rule]       ->  直抄，去掉逗号后的空格；AND/OR/NOT 结构原样保留；FINAL/MATCH 丢弃
[Rewrite]    ->  reject*        -> [Map Local]
                 redirect(n,url) -> [URL Rewrite] 302/307
                 body.mock(...)  -> [Map Local] (base64 载荷，避开引号冲突)
                 json.jq/delete/body.replace/header.set -> 无法映射，丢弃并记账
[Script]     ->  Loon Script v2  ->  Surge 现代写法 type=/pattern=/script-path=
[Key]        ->  Loon 的 ${x} 引号 -> Surge 的 {{{x}}} 占位符

零依赖，仅标准库。
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- 正则

SECTION_RE = re.compile(r"^\s*\[\s*([A-Za-z0-9 _\-]+?)\s*\]\s*$")
META_RE = re.compile(r"^#!\s*([A-Za-z0-9_\-]+)\s*=\s*(.*?)\s*$")

# Loon Script v2 / Rewrite v2 通用外壳
#   request|response  if <cond>  then <action>
SHELL_RE = re.compile(
    r"^(?P<trigger>request|response)\s+if\s+(?P<cond>.+?)\s+then\s+(?P<action>.+)$",
    re.I | re.S,
)

# ${url} ~= /regex/flags      或      ${url} == "https://..."
COND_RE = re.compile(r'^\s*\$\{url\}\s*(?P<op>~=|==)\s*(?P<rhs>.+?)\s*(?:\s+as\s+\w+)?\s*$', re.S)

SCRIPT_CALL_RE = re.compile(
    # script("url")  /  script("url", {${a}, ${b}})  [with k=v, ...]
    r'^script\(\s*"(?P<path>[^"]+)"\s*(?:,\s*\{(?P<vars>.*?)\})?\s*\)'
    r'(?:\s+with\s+(?P<params>.+))?$',
    re.I | re.S,
)

RE_REJECT = re.compile(r"^reject\(\s*(?P<code>\d{3})\s*\)$")
RE_REJECT_KIND = re.compile(r"^reject_(?P<kind>dict|array|img|json|200|tinygif)\(\s*(?P<code>\d{3})\s*\)$")
RE_REDIRECT = re.compile(r'^redirect\(\s*(?P<code>\d{3})\s*,\s*"(?P<url>[^"]*)"\s*\)$')

# 字符串字面量：支持 \" \\ 转义
STR_LIT = r'"(?:[^"\\]|\\.)*"'
BT_LIT = r"`[^`]*`"

RE_MOCK = re.compile(
    r'^response\.body\.mock(?P<file>_file)?\(\s*"(?P<kind>\w+)"\s*,\s*'
    r'(?P<body>' + STR_LIT + r"|" + BT_LIT + r")\s*"
    r"(?:,\s*(?P<code>\d{3}))?\s*(?:,\s*(?P<raw>true|false))?\s*\)$",
    re.S,
)
RE_HEADER_SET = re.compile(
    r'^response\.header\.set\(\s*"(?P<k>[^"]+)"\s*,\s*"(?P<v>[^"]*)"\s*\)$'
)

ARGNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
PH_LOON_RE = re.compile(r"\$\{([^}]+)\}")

RULE_PASSTHROUGH_HEADS = {"AND", "OR", "NOT"}
RULE_DROP_HEADS = {"FINAL", "MATCH"}
# IP-CIDR / IP-CIDR6 一律补 no-resolve，避免匹配时触发 DNS 解析
RULE_IP_HEADS = {"IP-CIDR", "IP-CIDR6"}
# Surge 模块内能用的内置策略。模块引用 profile 里不存在的策略会被报 unknown policy，
# 而 Loon 的 PROXY 在 Surge 里并不存在，所以源头的非内置策略统一落到 REJECT。
BUILTIN_POLICIES = {
    "DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP",
}

RE_TRAILING_COMMENT = re.compile(r"\s*//.*$")
RE_POLICY_TAIL = re.compile(r",\s*(?:DIRECT|REJECT(?:-[A-Z]+)?)\s*$", re.I)

MAX_LINE = 8000  # 单行兜底长度，超过就截断并记日志

# ---------------------------------------------------------------- 工具


def split_unquoted(s: str, sep: str = ",") -> list[str]:
    """按 sep 切分，引号（" ' `）内的分隔符不切，支持反斜杠转义。"""
    out: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
            buf.append(ch)
        elif ch == sep:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'`":
        return v[1:-1]
    return v


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def unescape_literal(s: str) -> str:
    """还原 JS 字符串字面量里的转义：\\" \\' \\/ """
    return s.replace('\\"', '"').replace("\\'", "'").replace("\\/", "/")


def loon_placeholder_to_surge(value: str) -> str:
    """${x} -> {{{x}}}；其它原样。"""
    return PH_LOON_RE.sub(lambda m: "{{{" + m.group(1).strip() + "}}}", value)


def guard(line: str, log: list[str], where: str) -> str:
    if len(line) > MAX_LINE:
        log.append(f"{where}: 单行超长 {len(line)}，已保留")
    return line


# ---------------------------------------------------------------- 解析


def read_source(path: Path) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    meta: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    order: list[str] = []
    cur: str | None = None

    for raw in lines:
        m = SECTION_RE.match(raw)
        if m:
            cur = m.group(1).strip().lower()
            sections.setdefault(cur, [])
            if cur not in order:
                order.append(cur)
            continue
        mm = META_RE.match(raw)
        if mm and cur is None:
            meta[mm.group(1).lower()] = mm.group(2).strip()
            continue
        if cur is not None:
            sections[cur].append(raw)

    return meta, sections, order


def parse_arguments(lines: list[str]) -> list[tuple[str, str, str]]:
    """[Argument] -> [(名字, 类型, 默认值)]"""
    out: list[tuple[str, str, str]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, rhs = line.split("=", 1)
        name = name.strip()
        if not ARGNAME_RE.match(name):
            continue
        parts = [p.strip() for p in split_unquoted(rhs)]
        kind = parts[0].lower() if parts else "switch"
        if kind == "switch":
            default = unquote(parts[1]) if len(parts) > 1 else "true"
            # Loon 的 true/false 统一成 1/0，Surge 参数表里更好读
            default = "0" if default.lower() in ("false", "0", "no", "off") else "1"
        else:  # select / input / text ...
            default = unquote(parts[1]) if len(parts) > 1 else ""
        out.append((name, kind, default))
    return out


def build_argument_expr(names: list[str], bool_names: set[str]) -> str | None:
    """
    names -> Surge 脚本行的 argument= 值（含外层双引号）

    switch 型写裸数字 1/0：JS 里 "0" 是非空字符串（真值），只有数字 0 才是假值，
    所以必须裸写，否则开关关掉了脚本仍然会跑。
    select/input 型写带引号的字符串，保持原类型。
    """
    names = list(dict.fromkeys(n for n in names if n))
    if not names:
        return None
    parts = []
    for n in names:
        key = '\\"' + n + '\\":'
        if n in bool_names:
            parts.append(key + "{{{" + n + "}}}")
        else:
            parts.append(key + '\\"' + "{{{" + n + "}}}" + '\\"')
    return '"' + "{" + ",".join(parts) + "}" + '"'


# ---------------------------------------------------------------- Rule


def convert_rule_line(line: str, dropped: list[str], fixes: list[str]) -> str | None:
    s = line.strip()
    if not s:
        return ""
    if s.startswith("#"):
        return s

    # 源头存在 `REJECT //误杀` 这种把注释放进策略字段的脏数据，先剥掉
    clean = RE_TRAILING_COMMENT.sub("", s).strip()
    if not clean:
        return ""

    parts = [p.strip() for p in split_unquoted(clean)]
    head = parts[0].upper()

    if head in RULE_DROP_HEADS:
        dropped.append(f"[Rule] {s[:120]}")
        return None

    if head in RULE_PASSTHROUGH_HEADS:
        # AND/OR/NOT 内部含嵌套逗号，结构整体不动，只校验结尾策略
        if not RE_POLICY_TAIL.search(clean):
            fixed = re.sub(r",\s*[^,()]+\s*$", ",REJECT", clean)
            fixes.append(f"策略修正: {clean[:110]} -> {fixed[-40:]}")
            clean = fixed
        return clean

    if head in RULE_IP_HEADS:
        low = [p.lower() for p in parts]
        if "no-resolve" not in low:
            parts.append("no-resolve")

    # 策略字段合法性：模块内只能用 Surge 内置策略
    if len(parts) >= 2:
        idx = -1
        if parts[-1].lower() == "no-resolve" and len(parts) >= 3:
            idx = -2
        policy = parts[idx].strip()
        if policy.upper() not in BUILTIN_POLICIES:
            fixes.append(f"策略修正: {','.join(parts)[:110]} -> 策略 {policy} 改为 REJECT")
            parts[idx] = "REJECT"

    return ",".join(parts)


# ---------------------------------------------------------------- Rewrite


def cond_to_pattern(cond: str, dropped: list[str], where: str) -> str | None:
    """Loon 条件 -> Surge pattern 正则"""
    m = COND_RE.match(cond)
    if not m:
        dropped.append(f"{where} 条件无法解析: {cond[:100]}")
        return None

    op = m.group("op")
    rhs = m.group("rhs").strip()

    if op == "==":
        url = unquote(rhs)
        # 字面量 URL -> 锚定正则
        pat = re.escape(url).replace(r"\ ", " ")
        return "^" + pat + "$"

    # op == "~="  ->  /regex/flags  或  裸正则
    flags = ""
    if rhs.startswith("/"):
        end = rhs.rfind("/")
        if end > 0:
            flags = rhs[end + 1:].strip()
            rhs = rhs[1:end]
    pattern = rhs.replace("\\/", "/")
    if "i" in flags.lower() and not pattern.startswith("(?i)"):
        pattern = "(?i)" + pattern
    return pattern


def map_local_line(pattern: str, *, data: str | None, status: int, tiny_gif: bool = False) -> str:
    if tiny_gif:
        return f"{pattern} data-type=tiny-gif status-code={status}"
    if data is None:
        return f'{pattern} data-type=text data="" status-code={status}'
    return f'{pattern} data-type=base64 data="{data}" status-code={status}'


def convert_rewrite_line(
    line: str,
    map_local: list[str],
    url_rewrite: list[str],
    dropped: list[str],
) -> None:
    s = line.strip()
    if not s or s.startswith("#"):
        return

    m = SHELL_RE.match(s)
    if not m:
        dropped.append(f"[Rewrite] 语法无法识别: {s[:120]}")
        return

    trigger = m.group("trigger").lower()
    cond = m.group("cond")
    action = m.group("action").strip()
    where = f"[Rewrite/{trigger}]"

    pattern = cond_to_pattern(cond, dropped, where)
    if pattern is None:
        return

    # --- reject 家族 -> Map Local
    mm = RE_REJECT.match(action)
    if mm:
        map_local.append(map_local_line(pattern, data=None, status=int(mm.group("code"))))
        return

    mm = RE_REJECT_KIND.match(action)
    if mm:
        kind = mm.group("kind")
        code = int(mm.group("code"))
        if kind in ("img", "tinygif"):
            map_local.append(map_local_line(pattern, data=None, status=code, tiny_gif=True))
        elif kind in ("dict", "json"):
            map_local.append(map_local_line(pattern, data=b64("{}"), status=code))
        elif kind == "array":
            map_local.append(map_local_line(pattern, data=b64("[]"), status=code))
        else:  # reject_200
            map_local.append(map_local_line(pattern, data=None, status=code))
        return

    # --- redirect -> URL Rewrite
    mm = RE_REDIRECT.match(action)
    if mm:
        code = mm.group("code")
        target = loon_placeholder_to_surge(mm.group("url"))
        target = target.replace("{{{", "$").replace("}}}", "")  # {{{urlMatch.1}}} -> $urlMatch.1
        target = re.sub(r"\$urlMatch\.(\d+)", r"$\1", target)
        url_rewrite.append(f"{pattern} {target} {code}")
        return

    # --- body.mock / body.mock_file -> Map Local（可带 a | header.set(b,c) 管道）
    if action.startswith("response.body.mock"):
        segs = [x.strip() for x in split_unquoted(action, "|")]
        mm = RE_MOCK.match(segs[0])
        if mm:
            body = unescape_literal(unquote(mm.group("body")))
            code = int(mm.group("code") or 200)
            headers = []
            for extra in segs[1:]:
                hm = RE_HEADER_SET.match(extra)
                if hm:
                    headers.append(f"{hm.group('k')}:{hm.group('v')}")
            hdr = (' header="%s"' % "|".join(headers)) if headers else ""
            if mm.group("file"):
                # mock_file：本地直连远程文件，Map Local 的 file 类型原生支持 URL
                map_local.append(
                    f'{pattern} data-type=file data="{body}" status-code={code}{hdr}'
                )
            else:
                already = (mm.group("raw") or "").lower() == "true"
                payload = body if already else b64(body)
                map_local.append(
                    f'{pattern} data-type=base64 data="{payload}" status-code={code}{hdr}'
                )
            return

    # --- 其余（json.jq / json.delete / body.replace / header.set / url.replace ...）
    dropped.append(f"{where} 无 Surge 等价动作: {action[:110]}")


# ---------------------------------------------------------------- Script


def make_script_name(path: str, used: set[str]) -> str:
    base = path.split("?")[0].rstrip("/").split("/")[-1]
    base = re.sub(r"\.js$", "", base, flags=re.I)
    base = re.sub(r"[^A-Za-z0-9_.\-]", "_", base) or "script"
    if base[0].isdigit():
        base = "s_" + base
    name, i = base, 2
    while name in used:
        name = f"{base}{i}"
        i += 1
    used.add(name)
    return name


def convert_script_line(
    line: str,
    used_names: set[str],
    dropped: list[str],
    bool_names: set[str],
) -> str | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return line.rstrip()

    m = SHELL_RE.match(s)
    if not m:
        dropped.append(f"[Script] 语法无法识别: {s[:120]}")
        return None

    trigger = m.group("trigger").lower()
    pattern = cond_to_pattern(m.group("cond"), dropped, f"[Script/{trigger}]")
    if pattern is None:
        return None

    cm = SCRIPT_CALL_RE.match(m.group("action").strip())
    if not cm:
        dropped.append(f"[Script] 非 script() 动作: {m.group('action')[:110]}")
        return None

    script_path = cm.group("path")
    name = make_script_name(script_path, used_names)

    surge_params: list[str] = []
    arg_names: list[str] = []

    # 默认参数对象 script("x", {${a}, ${b}})：块内变量同样进 argument
    for pm in PH_LOON_RE.finditer(cm.group("vars") or ""):
        arg_names.append(pm.group(1).strip())

    for item in split_unquoted(cm.group("params") or ""):
        piece = item.strip()
        if not piece:
            continue
        k, _, v = piece.partition("=")
        k, v = k.strip(), v.strip()
        kl = k.lower()

        if kl == "tag":
            continue  # Surge 脚本行没有 tag
        if kl == "enable":
            pm = PH_LOON_RE.match(v)
            if pm:
                arg_names.append(pm.group(1).strip())
            continue
        if kl == "requires_body":
            on = v.lower() not in ("false", "0", "no")
            surge_params.append(f"requires-body={'true' if on else 'false'}")
            continue
        if kl == "binary_body_mode":
            on = v.lower() not in ("false", "0", "no")
            surge_params.append(f"binary-body-mode={'true' if on else 'false'}")
            continue
        if kl == "max_size":
            surge_params.append(f"max-size={'-1' if v in ('', '0') else v}")
            continue
        surge_params.append(f"{k}={loon_placeholder_to_surge(v)}")

    arg_expr = build_argument_expr(arg_names, bool_names)
    if arg_expr:
        surge_params.append(f"argument={arg_expr}")

    tail = ",".join(surge_params)
    head = f"type=http-{trigger},pattern={pattern},script-path={script_path}"
    body = f"{name} = {head},{tail}" if tail else f"{name} = {head}"
    return body


# ---------------------------------------------------------------- MITM


def convert_mitm(lines: list[str]) -> str | None:
    text = "\n".join(lines)
    if not text.strip():
        return None

    hosts: list[str] = []
    # 源文件存在两行 hostname 粘连的情况，按关键字切开
    for chunk in re.split(r"(?i)hostname\s*=\s*", text):
        for item in chunk.split(","):
            h = item.strip()
            if not h or h.lower().startswith("%append%"):
                continue
            if h.startswith("#"):
                continue
            hosts.append(h)

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return None
    return "hostname = %APPEND% " + ", ".join(hosts)


# ---------------------------------------------------------------- 主流程


META_ORDER = [
    "name", "desc", "author", "icon", "category",
    "homepage", "tag", "system", "date", "tg-channel", "remark",
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Loon plugin -> Surge module")
    ap.add_argument("--src", required=True, help="Loon .plugin 路径")
    ap.add_argument("--out", required=True, help="输出 .sgmodule 路径")
    ap.add_argument("--raw-url", default="", help="写进产物的订阅地址")
    ap.add_argument("--date", default="", help="覆盖 #!date 时间戳；留空沿用源文件值")
    ap.add_argument("--min-rules", type=int, default=0)
    ap.add_argument("--min-scripts", type=int, default=0)
    ap.add_argument("--min-hosts", type=int, default=0)
    ap.add_argument("--strict", action="store_true", help="任一项不达标则 exit 1")
    ap.add_argument("--no-arguments", action="store_true", help="不生成参数表")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"[FAIL] 源文件不存在: {src}", file=sys.stderr)
        return 2

    meta, sections, order = read_source(src)
    arglist = parse_arguments(sections.get("argument", []))
    bool_names = {n for n, k, _ in arglist if k == "switch"}
    dropped: list[str] = []
    log: list[str] = []

    # ---------- 各段转换 ----------
    fixes: list[str] = []
    rule_out: list[str] = []
    for ln in sections.get("rule", []):
        got = convert_rule_line(ln, dropped, fixes)
        if got is not None:
            rule_out.append(got)

    map_local: list[str] = []
    url_rewrite: list[str] = []
    for ln in sections.get("rewrite", []):
        convert_rewrite_line(ln, map_local, url_rewrite, dropped)

    used_names: set[str] = set()
    script_out: list[str] = []
    for ln in sections.get("script", []):
        got = convert_script_line(ln, used_names, dropped, bool_names)
        if got is not None:
            script_out.append(got)

    mitm_line = convert_mitm(sections.get("mitm", []))

    # ---------- 统计 ----------
    n_rule = sum(1 for x in rule_out if x.strip() and not x.strip().startswith("#"))
    n_script = sum(1 for x in script_out if x.strip() and not x.strip().startswith("#"))
    n_host = 0
    if mitm_line:
        n_host = len([h for h in mitm_line.split("%APPEND%", 1)[1].split(",") if h.strip()])

    # ---------- 组装 ----------
    out: list[str] = []
    for k in META_ORDER:
        if k == "date" and args.date:
            out.append(f"#!date={args.date}")
            continue
        if meta.get(k):
            val = meta[k]
            if k == "system":
                val = "ios"
            out.append(f"#!{k}={val}")
    if not meta.get("system"):
        out.append("#!system=ios")

    if args.raw_url:
        out.append(f"#!raw-url={args.raw_url}")

    if arglist and not args.no_arguments:
        out.append("#!arguments=" + ",".join(f"{n}:{d}" for n, _, d in arglist))
        out.append(
            "#!arguments-desc=各 APP 去广告开关，0=关 1=开；改完需要在 Surge 里重新加载本模块才会生效"
        )

    out.append("")
    out.append("# ============================================================")
    out.append(f"# 由 Loon 插件自动转换  {src.name}")
    out.append(f"# 规则 {n_rule} 条 / 脚本 {n_script} 条 / MITM 主机 {n_host} 个")
    out.append(f"# 未能映射被丢弃 {len(dropped)} 项（明细见文件末尾注释）")
    out.append("# ============================================================")
    out.append("")

    if url_rewrite:
        out.append("[URL Rewrite]")
        out.extend(url_rewrite)
        out.append("")

    if rule_out:
        out.append("[Rule]")
        out.extend(rule_out)
        out.append("")

    if map_local:
        out.append("[Map Local]")
        out.extend(map_local)
        out.append("")

    if script_out:
        out.append("[Script]")
        out.extend(script_out)
        out.append("")

    if mitm_line:
        out.append("[MITM]")
        out.append(guard(mitm_line, log, "[MITM]"))
        out.append("")

    if fixes:
        out.append("# ------- 策略字段已修正（Surge 模块内只允许内置策略）-------")
        for fx in fixes[:200]:
            out.append("# " + fx.replace("\n", " ")[:200])
        out.append("")

    if dropped:
        out.append("# ---------------- 以下条目无 Surge 等价语法，已丢弃 ----------------")
        for d in dropped[:400]:
            out.append("# " + d.replace("\n", " ")[:200])
        if len(dropped) > 400:
            out.append(f"# … 另有 {len(dropped) - 400} 条未列出")
        out.append("")

    text = "\n".join(out).rstrip() + "\n"
    dst = Path(args.out)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")

    # ---------- 自检 ----------
    print(f"[out] {dst}  {len(text)} 字符")
    print(
        f"[stat] 规则 {n_rule} / 脚本 {n_script} / MITM {n_host} / "
        f"参数 {len(arglist)} / 丢弃 {len(dropped)} / 策略修正 {len(fixes)}"
    )

    errs: list[str] = []
    if "max-size=0" in text:
        errs.append("残留 max-size=0（Surge 会当成 0 字节上限）")

    bad_policy: list[str] = []
    for ln in rule_out:
        t = ln.strip()
        if not t or t.startswith("#"):
            continue
        seg = [x.strip() for x in split_unquoted(t)]
        if len(seg) < 2:
            continue
        i = -1
        if seg[-1].lower() == "no-resolve" and len(seg) >= 3:
            i = -2
        if seg[i].upper() not in BUILTIN_POLICIES:
            bad_policy.append(t)
    if bad_policy:
        errs.append(f"{len(bad_policy)} 条规则用了非内置策略: {bad_policy[0][:90]}")
    if re.search(r"^\s*(FINAL|MATCH)\s*,", text, re.M):
        errs.append("残留 FINAL/MATCH 规则")
    if arglist and not args.no_arguments:
        if "{{{" in text and "#!arguments=" not in text:
            errs.append("有占位符但缺 #!arguments 声明")
        # 每个占位符都必须在参数表里有声明
        declared = {n for n, _, _ in arglist}
        for ph in set(re.findall(r"\{\{\{([A-Za-z0-9_]+)\}\}\}", text)):
            if ph not in declared:
                errs.append(f"占位符 {{{{{ph}}}}} 未在 #!arguments 中声明")
    if args.min_rules and n_rule < args.min_rules:
        errs.append(f"规则 {n_rule} < 下限 {args.min_rules}")
    if args.min_scripts and n_script < args.min_scripts:
        errs.append(f"脚本 {n_script} < 下限 {args.min_scripts}")
    if args.min_hosts and n_host < args.min_hosts:
        errs.append(f"MITM 主机 {n_host} < 下限 {args.min_hosts}")

    for e in errs:
        print(f"[FAIL] {e}", file=sys.stderr)
    for w in log:
        print(f"[warn] {w}", file=sys.stderr)

    if errs and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

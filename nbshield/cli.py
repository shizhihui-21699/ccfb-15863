"""命令行接口。

用法::

    nbshield check untrusted.ipynb                 # 只检测,不写文件
    nbshield sanitize in.ipynb -o out.ipynb        # 净化并写出
    nbshield sanitize in.ipynb --policy strict     # 严格模式
    nbshield sanitize in.ipynb --report r.json --format json
    nbshield batch DIR/ -o OUT/ --fail-on high     # 批量

退出码:0 无问题(或低于 --fail-on)、1 达到阈值、2 用法/输入错误。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .model import Report, Severity
from .policy import PRESETS, Policy, get_policy
from .processor import ProcessResult, process_notebook
from .sarif import to_sarif


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _format_report(report: Report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    if fmt == "sarif":
        return json.dumps(to_sarif([report]), ensure_ascii=False, indent=2)
    return report.summary()


def _build_policy(args: argparse.Namespace) -> Policy:
    try:
        pol = get_policy(getattr(args, "policy", "balanced"))
    except ValueError as exc:
        raise SystemExit(f"nbshield: {exc}")
    overrides = {}
    if getattr(args, "no_csp", False):
        overrides["inject_csp"] = False
    if getattr(args, "allow_iframes", False):
        overrides["allow_iframes"] = True
    if getattr(args, "neutralize_magics", False):
        overrides["neutralize_magics"] = True
    if getattr(args, "strip_outputs", False):
        overrides["strip_outputs"] = True
    if getattr(args, "max_bytes", None):
        overrides["max_bytes"] = args.max_bytes
    strip_at = getattr(args, "script_strip_at", None)
    if strip_at:
        overrides["script_strip_at"] = Severity.from_name(strip_at)
    if overrides:
        pol = pol.replace(**overrides)
    return pol


def _threshold(args: argparse.Namespace) -> Severity:
    raw = getattr(args, "fail_on", None)
    if not raw:
        return Severity.CRITICAL
    return Severity.from_name(raw)


def cmd_check(args: argparse.Namespace) -> int:
    pol = _build_policy(args)
    try:
        data = _read(args.input)
    except OSError as exc:
        print(f"nbshield: 无法读取 {args.input}: {exc}", file=sys.stderr)
        return 2
    res = process_notebook(data, pol, source=args.input)
    print(_format_report(res.report, args.format))
    if args.output and args.format != "json" and args.format != "sarif":
        _write(args.output, _format_report(res.report, args.format).encode("utf-8"))
    sev = res.report.max_severity
    if args.fail_on and sev >= _threshold(args):
        return 1
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    pol = _build_policy(args)
    try:
        data = _read(args.input)
    except OSError as exc:
        print(f"nbshield: 无法读取 {args.input}: {exc}", file=sys.stderr)
        return 2
    res = process_notebook(data, pol, source=args.input)

    out = args.output or _default_output(args.input)
    if res.notebook:
        _write(out, res.text.encode("utf-8"))
    elif args.keep_blocked:
        # 结构被拒绝,默认不写文件;显式要求时写报告
        pass

    if args.report:
        _write(args.report, _format_report(res.report, args.format).encode("utf-8"))
    print(_format_report(res.report, args.format))

    if res.report.blocked and not args.accept_risk:
        print(
            f"nbshield: 阻断 —— {res.report.block_reason}(已写净化文件到 {out},"
            f"请人工复核后再使用;如确需放行加 --accept-risk)",
            file=sys.stderr,
        )
        return 1
    if args.fail_on and res.report.max_severity >= _threshold(args):
        return 1
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    pol = _build_policy(args)
    src_dir = args.input
    dst_dir = args.output or (src_dir.rstrip("/\\") + "_clean")
    if not os.path.isdir(src_dir):
        print(f"nbshield: 不是目录: {src_dir}", file=sys.stderr)
        return 2
    reports: List[Report] = []
    failures = 0
    worst = Severity.INFO
    for name in sorted(os.listdir(src_dir)):
        if not name.lower().endswith(".ipynb"):
            continue
        path = os.path.join(src_dir, name)
        try:
            data = _read(path)
        except OSError as exc:
            print(f"nbshield: 跳过 {name}: {exc}", file=sys.stderr)
            failures += 1
            continue
        res = process_notebook(data, pol, source=path)
        reports.append(res.report)
        worst = max(worst, res.report.max_severity)
        if res.notebook:
            _write(os.path.join(dst_dir, name), res.text.encode("utf-8"))
        if res.report.blocked and not args.accept_risk:
            failures += 1
        print(f"{name}: {res.report.max_severity.label} "
              f"({len(res.report.findings)} findings)"
              + (" [BLOCKED]" if res.report.blocked else ""))
    if args.report:
        if args.format == "sarif":
            payload = json.dumps(to_sarif(reports), ensure_ascii=False, indent=2)
        else:
            payload = json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2)
        _write(args.report, payload.encode("utf-8"))
    if failures:
        return 1
    if args.fail_on and worst >= _threshold(args):
        return 1
    return 0


def _default_output(path: str) -> str:
    root, ext = os.path.splitext(path)
    return root + ".clean" + (ext or ".ipynb")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nbshield",
        description="不可信 Jupyter 笔记本的静态检测与净化(打开即执行的活动内容)。",
    )
    p.add_argument("--version", action="version", version=f"nbshield {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--policy", choices=sorted(PRESETS), default="balanced",
                        help="策略预设(默认 balanced)")
        sp.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="报告格式")
        sp.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                        help="达到该级别时返回退出码 1")
        sp.add_argument("--script-strip-at", choices=["medium", "high", "critical"],
                        help="脚本判定达到该级别即移除")
        sp.add_argument("--no-csp", action="store_true", help="不注入 CSP meta")
        sp.add_argument("--allow-iframes", action="store_true",
                        help="允许 iframe(强制 sandbox)")
        sp.add_argument("--neutralize-magics", action="store_true",
                        help="中和 %%javascript/%%html 魔法")
        sp.add_argument("--strip-outputs", action="store_true", help="移除所有输出")
        sp.add_argument("--max-bytes", type=int, default=None)

    c = sub.add_parser("check", help="只检测,不写出笔记本")
    c.add_argument("input")
    c.add_argument("-O", "--output", help="把报告写入文件")
    common(c)
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("sanitize", help="净化并写出笔记本")
    s.add_argument("input")
    s.add_argument("-o", "--output", help="输出路径(默认 <input>.clean.ipynb)")
    s.add_argument("--report", help="发现项报告路径")
    s.add_argument("--accept-risk", action="store_true",
                   help="即使检测到确凿恶意内容也返回 0(文件已净化)")
    s.add_argument("--keep-blocked", action="store_true")
    common(s)
    s.set_defaults(func=cmd_sanitize)

    b = sub.add_parser("batch", help="批量处理目录")
    b.add_argument("input")
    b.add_argument("-o", "--output")
    b.add_argument("--report")
    b.add_argument("--accept-risk", action="store_true")
    common(b)
    b.set_defaults(func=cmd_batch)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在线更新的安全边界回归。

更新通道本身是攻击面: 一个能被喂恶意包的更新器, 比不更新危险得多。
这里逐条验四件事:

  [1] 版本比较(只升不降)
  [2] zip slip —— 更新包里的 `../` / 绝对路径 / 盘符一律拒绝
  [3] 受保护文件 —— state/ out/ bin/ 订阅地址.txt 不会被包里的同名文件覆盖
  [4] 下载只走 https, 且包内版本号要与远端声明一致

跑法: python state/test_updater.py
"""
from __future__ import annotations

import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, r"E:\AI\freeVPN")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import updater  # noqa: E402

WORK = Path(r"E:\AI\freeVPN\state\_updtest")
PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def make_zip(path: Path, members: dict[str, str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def main() -> int:
    print("=" * 74)
    print("  freeVPN 在线更新 · 安全边界回归")
    print("=" * 74)
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)

    print("\n[1] 版本比较")
    check("ver_tuple('v1.4.10') -> (1,4,10)", updater.ver_tuple("v1.4.10") == (1, 4, 10))
    check("ver_tuple('1.4') -> (1,4,0)", updater.ver_tuple("1.4") == (1, 4, 0))
    check("ver_tuple('') 不抛异常", updater.ver_tuple("") == (0, 0, 0))
    check("1.4.10 > 1.4.9", updater.is_newer("1.4.10", "1.4.9"))
    check("1.4.1 不比 1.4.1 新(不降级)", not updater.is_newer("1.4.1", "1.4.1"))
    check("1.3.9 不比 1.4.0 新(防降级)", not updater.is_newer("1.3.9", "1.4.0"))

    print("\n[2] zip slip 防护")
    evil_cases = {
        "相对穿越 ../": {"../evil.txt": "x"},
        "深穿越 ../../": {"a/../../../evil.txt": "x"},
        "绝对路径": {"/tmp/evil.txt": "x"},
        "Windows 盘符": {"C:/Windows/evil.txt": "x"},
        "反斜杠穿越": {"..\\evil.txt": "x"},
    }
    for label, members in evil_cases.items():
        zp = WORK / "evil.zip"
        make_zip(zp, members)
        dest = WORK / "evil_out"
        shutil.rmtree(dest, ignore_errors=True)
        try:
            updater.extract_package(zp, dest)
            check(f"拒绝 {label}", False, "竟然解压成功了")
        except ValueError as e:
            check(f"拒绝 {label}", True, str(e)[:48])
        except Exception as e:
            check(f"拒绝 {label}", False, f"抛了别的异常 {type(e).__name__}: {e}")

    print("\n[3] 受保护文件不被覆盖")
    good = {
        "freeVPN-1.4.2/pool.py": "print('new')",
        "freeVPN-1.4.2/VERSION": "freeVPN 1.4.2\nrelease 2026-10-10\n",
        "freeVPN-1.4.2/state/token.txt": "ATTACKER-TOKEN",
        "freeVPN-1.4.2/out/freevpn.yaml": "proxies: []",
        "freeVPN-1.4.2/bin/mihomo.exe": "MZ-fake",
        "freeVPN-1.4.2/订阅地址.txt": "http://evil/",
        "freeVPN-1.4.2/README.md": "# new readme",
    }
    zp = WORK / "good.zip"
    make_zip(zp, good)
    dest = WORK / "good_out"
    shutil.rmtree(dest, ignore_errors=True)
    root, n = updater.extract_package(zp, dest)
    check("正常包解压成功", n == 3, f"写入 {n} 个文件(应为 3: pool.py/VERSION/README.md)")
    check("剥掉了包内前缀目录", (root / "pool.py").exists())
    check("state/ 没被写入", not (root / "state").exists())
    check("out/ 没被写入", not (root / "out").exists())
    check("bin/ 没被写入", not (root / "bin").exists())
    check("订阅地址.txt 没被写入", not (root / "订阅地址.txt").exists())
    check("包内版本号读得出", updater.package_version(root) == "1.4.2",
          updater.package_version(root))

    print("\n[4] 下载与来源约束")
    try:
        updater.download("http://example.com/x.zip", WORK / "x.zip", quiet=True)
        check("拒绝非 https 的更新包", False, "竟然接受了")
    except ValueError as e:
        check("拒绝非 https 的更新包", True, str(e)[:48])
    except Exception as e:
        check("拒绝非 https 的更新包", False, f"{type(e).__name__}: {e}")
    check("更新源是写死的常量(不是参数)",
          isinstance(updater.REPO, str) and "/" in updater.REPO
          and not hasattr(updater, "set_repo"), updater.REPO)
    check("体积上限已设", updater.MAX_PACKAGE_BYTES > 0,
          f"{updater.MAX_PACKAGE_BYTES // 1048576}MB")

    shutil.rmtree(WORK, ignore_errors=True)
    print("\n" + "=" * 74)
    print(f"  通过 {len(PASS)} / 失败 {len(FAIL)}")
    for f in FAIL:
        print(f"    FAIL: {f}")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

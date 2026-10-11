#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""版本信息 —— 单一定义点，pool / gui / pack 都从这里取。"""

__version__ = "1.6.6"

# 版本号含义（语义化）：
#   主版本  不兼容的改动（配置格式、产物结构、命令行接口）
#   次版本  向后兼容的功能新增
#   修订号  向后兼容的缺陷修复
#
# 改版本号时同步更新 CHANGELOG.md。
__release_date__ = "2026-10-11"

__title__ = "freeVPN"
__app_name__ = "freeVPN"


def version_string() -> str:
    return f"{__title__} v{__version__} ({__release_date__})"

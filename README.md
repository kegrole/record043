# redact — 日志脱敏器

纯 Python 标准库实现的日志脱敏工具，支持 JSON Lines 与 logfmt 两种日志格式，
按规则文件中的键路径规则对敏感字段做不可逆脱敏，同时保持日志结构不变。

## 运行

```bash
python -m redact.cli --input demo/logs.jsonl --rules demo/redact_rules.json --out out/redacted.jsonl
```

运行结束后 stdout 打印一行摘要：总行数、被脱敏的行数与字段数、各规则命中分布。

## 日志格式

- **JSON Lines**：每行一个 JSON 对象。
- **logfmt**：每行 `key=value` 对，值可用双引号包裹（支持空格与转义）。

每行独立判定格式。没有任何字段命中规则的行逐字节原样输出，一个字符都不变。

## 键路径规则语法

规则文件是 JSON：`{"rules": [{"path": "...", "method": "..."}]}`，按声明顺序匹配，先中先生效。

- 路径以 `.` 分段，如 `user.password` 为精确路径。
- `*` 匹配恰好一层任意键，如 `user.*`（结尾通配）。
- `**` 匹配零层或多层任意键，如 `**.password` 可命中顶层、任意深度嵌套对象里的 `password`。
- 数组透明穿透：数组不增加路径层级，`items` 数组每个元素里的 `password` 路径都是 `items.password`，同样被 `**.password` 命中。
- 未命中任何规则的字段一律原样保留。

脱敏的键集合完全由规则文件决定：增删规则即改变脱敏范围，代码不内置任何键清单。

## 三种脱敏方式

| method    | 行为 | 示例 |
|-----------|------|------|
| `keep`    | 保留前 2 位与后 2 位，中间以 `*` 填充；长度 ≤4 的值整体打星 | `Sup3rSecret!` → `Su********t!` |
| `replace` | 整体替换为固定占位符 | 字符串 → `***REDACTED***`，数字 → `0` |
| `hash`    | `sha256:` 前缀 + SHA-256 摘要前 16 位十六进制 | `a@b.com` → `sha256:…` |

三种方式都不可逆：输出中不会出现原值的任何连续 4 个字符。

## 结构保持约定

- 键的顺序与输入完全一致（JSON 对象按插入顺序序列化）。
- 值的 JSON 类型不变：数字脱敏后仍是数字（`replace` → `0`，`keep` → 保留首尾数字中间补 0 的整数，`hash` → 由摘要派生的整数），字符串仍是字符串，数组与对象形状不变。
- 输出格式与输入格式一致：JSON 行输出 JSON，logfmt 行输出 logfmt。

## 测试

```bash
python -m unittest discover -s tests -v
```

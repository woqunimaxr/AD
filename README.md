# AD — Loon 去广告插件 → Surge 模块自动转换

把 [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts) 的 Loon 版去广告插件，
每天自动转换成 Surge 可用的 `.sgmodule`，产物落在 `surge/`。

## 数据流

```
Loon/plugin/blockAds.plugin   (上游, 每日拉取)
        │
        ▼  scripts/loon2surge.py
surge/blockAds.sgmodule       (本仓库产物, 带 #!arguments 参数表)
        │
        ▼
Surge 订阅 raw 链接
```

## Surge 订阅地址

```
https://raw.githubusercontent.com/woqunimaxr/AD/main/surge/blockAds.sgmodule
```

## 转换规则

| Loon | Surge | 说明 |
|---|---|---|
| `[Argument]` `x = switch,true,false` | `#!arguments=x:true` | 开关声明 |
| `${x}`（脚本里的引用） | `{{{x}}}` | 占位符，Surge 在应用模块前替换 |
| `[Rule]` `DOMAIN-SUFFIX, a.com, REJECT` | `DOMAIN-SUFFIX,a.com,REJECT` | 去掉逗号后空格 |
| `IP-CIDR` / `IP-CIDR6` | 末尾自动补 `no-resolve` | 避免触发 DNS 解析 |
| `AND` / `OR` / `NOT` 嵌套规则 | 原样保留 | 内部逗号结构不动 |
| `FINAL` / `MATCH` | 丢弃 | 模块规则插在规则表顶端，会吃掉全部流量 |
| `reject(404)` | `[Map Local] ... status-code=404` | |
| `reject(200)` | `[Map Local] ... data="" status-code=200` | |
| `reject_dict(200)` | `[Map Local] ... data="e30="` | `{}` 的 base64 |
| `reject_img(200)` | `[Map Local] ... data-type=tiny-gif` | 1px GIF |
| `redirect(n, "url")` | `[URL Rewrite] ... url n` | |
| `response.body.mock(...)` | `[Map Local]` base64 载荷 | |
| `request/response if ... then script("u") with ...` | `名 = type=http-request/response,pattern=...,script-path=...` | Loon Script v2 |
| `script("u", {${a}, ${b}})` | 变量写入 `argument` JSON | |
| `requires_body` / `binary_body_mode` | `requires-body` / `binary-body-mode` | |
| `tag="x"` | 丢弃 | Surge 脚本行无 tag |
| `response.json.jq(...)` `json.delete(...)` `body.replace(...)` `header.set(...)` | 丢弃并记账 | Surge 无等价语法，明细见 sgmodule 末尾注释 |

## 部署

1. 建仓库 `woqunimaxr/AD`，把本目录内容推上去（保持 `.github/`、`scripts/`、`surge/` 结构）。
2. `Settings → Actions → General → Workflow permissions` 选 **Read and write**，否则定时任务推送会 401。
3. `Actions` 页手动跑一次 `build blockAds`，确认产物生成。
4. 在 Surge 里订阅上面的 raw 链接。

## 工作流

`.github/workflows/build-blockads.yml`

- 每天北京时间 00:43 跑一次（UTC `43 16 * * *`）
- 也支持手动 `workflow_dispatch`，以及改 `scripts/` 后自动触发
- 硬断言：规则 ≥ 2000、脚本 ≥ 200、MITM 主机 ≥ 800，任一项不达标就失败、不提交
- 残留检查：`max-size=0`、`FINAL`/`MATCH`、缺 `no-resolve` 的 IP-CIDR，命中任一即失败

## 本地跑

```bash
curl -fsSL -o _tmp-src/blockAds.plugin \
  https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/plugin/blockAds.plugin

python scripts/loon2surge.py \
  --src _tmp-src/blockAds.plugin \
  --out surge/blockAds.sgmodule \
  --min-rules 2000 --min-scripts 200 --min-hosts 800 --strict
```

# My ZJU-Rule 独立仓库自定义分流规则使用指南

本仓库基于 [SubConv/ZJU-Rule](https://github.com/SubConv/ZJU-Rule) 整理而来，已脱离原仓库 Git 历史并移除原项目的 `.github/workflows`（避免推送时触发不必要的 Actions 邮件），采用清晰的**双分支独立结构**：

- `main`：干净的导入基线分支（不含自定义改动）。
- `my-rules`：当前工作分支，所有个人网站分流规则统一写在 `my_rules.yaml` 中，一键生成高优先级 `Clash/config/MyZJU.ini` 供 Subconverter 使用。

---

## 一、日常修改网站规则（只需 3 步）

1. **编辑 [`my_rules.yaml`](./my_rules.yaml)**：在对应分类下添加或删除网站域名（默认置顶生效，优先级高于上游规则）。
2. **运行生成脚本**（无需任何第三方 Python 库）：
   ```powershell
   python apply_my_rules.py
   ```
   - 仅校验预览不写文件：`python apply_my_rules.py --dry-run`
   - 查看所有可用分类别名与 `ZJU.ini` 策略组：`python apply_my_rules.py --list-groups`
3. **提交并推送到你的 GitHub 分支**：
   ```powershell
   git add my_rules.yaml Clash/config/MyZJU.ini Clash/Custom Clash/Providers/Custom
   git commit -m "update custom vpn rules"
   git push origin my-rules
   ```
   > 提示：若当前终端未识别 `git` 命令，新开一个 PowerShell 窗口即可（已通过 `winget` 在用户目录安装便携版 `Git.MinGit` 并自动写入用户 PATH）。

---

## 二、`my_rules.yaml` 支持的简写格式

| 你写的内容 | 自动转换后的 Clash / Subconverter 规则 | 说明 |
| --- | --- | --- |
| `example.com` | `DOMAIN-SUFFIX,example.com` | 匹配主域及所有子域（最常用） |
| `*.example.com` / `.example.com` | `DOMAIN-SUFFIX,example.com` | 同上 |
| `=www.example.com` | `DOMAIN,www.example.com` | 仅精确匹配该完整主机名 |
| `*openai` | `DOMAIN-KEYWORD,openai` | 域名包含关键词即匹配 |
| `https://sub.example.com/path` | `DOMAIN-SUFFIX,sub.example.com` | 直接粘贴完整网址也可自动提取域名 |
| `1.2.3.4` / `1.2.3.0/24` | `IP-CIDR,1.2.3.4/32,no-resolve` / `IP-CIDR,1.2.3.0/24,no-resolve` | IPv4 自动转 `IP-CIDR`，IPv6 自动转 `IP-CIDR6` |
| `DOMAIN-SUFFIX,foo.com` | `DOMAIN-SUFFIX,foo.com` | 原生规则语法原样保留 |

### 常用分组别名

- `direct` -> `🎯 全球直连`
- `proxy` -> `🚀 节点选择`
- `zju` -> `✔ ZJU内网`
- `scholar` -> `📃 ZJU More Scholar`
- `ai` -> `💬 Ai平台`
- `foreign_media` / `china_media` / `youtube` / `netflix` / `bilibili` / `telegram` / `games` / `reject`
- 地区节点：`region_hk`、`region_jp`、`region_us`（`🇺🇲 美国节点`）、`region_tw`、`region_sg`、`region_kr`
- 任意其他策略组：在 `custom_groups` 中按 `ZJU.ini` 的完整名称填写（例如 `"Ⓜ️ 微软服务"`）。

---

## 三、首次推送到自己的独立 GitHub 仓库

1. 在 GitHub 上新建一个**空白仓库**（注意：创建时**不要勾选**初始化 `README`、`.gitignore` 或 `License`）。
2. 在本仓库目录设置你的 Git 作者信息、绑定 `origin` 并推送 `main` 与 `my-rules` 两个分支：
   ```powershell
   git config user.name "你的名字"
   git config user.email "你的邮箱"
   git remote add origin https://github.com/<你的GitHub用户名>/<你的仓库名>.git
   git push -u origin main my-rules
   ```
3. 将以下链接填入 Subconverter 的 **远程配置（Remote Config）**：
   ```text
   https://raw.githubusercontent.com/<你的GitHub用户名>/<你的仓库名>/my-rules/Clash/config/MyZJU.ini
   ```
   - 默认 `ruleset_mode: "inline"` 会把你的自定义规则直接以内联 `[]` 形式置顶写入 `MyZJU.ini`，无需额外请求 `.list` 文件，转换更快、开箱即用。
   - 如需改为外部 `.list` 链接模式，或将全套规则链接也切换为指向自己的独立仓库，只需调整 `my_rules.yaml` 中 `github.ruleset_mode` / `github.upstream_mode` 后重新运行 `python apply_my_rules.py`。

---

## 四、如何按需更新上游规则

- **默认自动跟随（无需手动操作）**：`my_rules.yaml` 中 `github.upstream_mode` 默认为 `"upstream"`，这意味着 `Clash/config/MyZJU.ini` 里的自定义规则来自你的独立仓库，而其余上游 `.list` 规则链接会自动跟随 `SubConv/ZJU-Rule` 的每日更新，通常无需手动同步本地仓库。
- **如需刷新本地基线文件**：可切回 `main` 分支替换为新版上游文件并提交，然后切回 `my-rules` 执行：
  ```powershell
  git checkout my-rules
  git merge main
  python apply_my_rules.py
  git add Clash/config/MyZJU.ini
  git commit -m "chore: rebuild MyZJU.ini after baseline refresh"
  git push origin my-rules
  ```

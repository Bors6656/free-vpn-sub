# Free Sub

每小时自动更新免费 Clash 订阅。  
部署到 GitHub Actions，订阅直链走 raw.githubusercontent.com CDN，无请求次数限制。

## 使用

### 1. Fork 到你的 GitHub
仓库地址：  
`https://github.com/<你的用户名>/free-vpn-sub`

### 2. 在 GitHub 启用 Actions
进入仓库 → Actions → 找到 "Update Free Sub" → 点 "Enable workflow"

> 如果 fork 后 Actions 没跑，需要手动开一次，否则 GitHub 会禁 fork 仓库的 Actions。

### 3. 订阅链接
```text
https://raw.githubusercontent.com/<你的用户名>/free-vpn-sub/main/dist/clash.yaml
```

把上面链接粘贴到 FlClash / Clash Verge / ClashX 订阅即可。

开启 **自动更新**，以后每小时自动换最新节点。

## 自定义

- 编辑 `SOURCES` 列表替换为你想用的公益源  
- 每小时触发：`.github/workflows/update.yml` 里的 cron 表达式
- 需要手动触发：GitHub Actions → Run workflow

## 注意

- 免费公益节点质量不稳定，偶尔抽风属正常
- 如果源全部失效，GitHub Actions 仍会生成空文件，请替换 SOURCES
- raw.githubusercontent.com 在国内偶有被墙，可开启本仓库的 GitHub Pages，改走你的 gh-pages 域名

## 本地测试
```bash
pip install pyyaml
python build.py
```
产物在 `dist/clash.yaml`。

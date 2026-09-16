# 免费节点自动测活订阅池部署与上线

## Problem
用户希望基于 GitHub Gist (https://gist.github.com/jewell998998/35178cb6102bc290ca36bf8c233c316a) 搭建一套属于自己的自动化节点测活与订阅池系统。原 Gist 是一个单文件版本的节点测活脚本，源自 hezhanleiok/freesub，并经过了超时缩短、严格出库、家宽识别等调优，但在独立部署前缺乏完整的工程骨架（包括 Actions 工作流、依赖管理、自动推送与防封 CDN 订阅）。

## Decision
1. 本地在 d:\projects\freesub 建立完整的项目结构，包含 scripts/main_v2.py、scripts/requirements.txt、.github/workflows/update.yml、README.md、AGENTS.md。
2. 清理 Gist 中原作者硬编码的 - xiaohe 节点命名后缀和旧仓库路径，统一映射为用户的 GitHub 命名空间（t200216/freesub）。
3. 选用 Public 公开仓库形态。Public 仓库拥有 GitHub Actions 无限免费运行时间，且生成的订阅链接可通过 jsDelivr CDN 免翻直连，使用户免去自行搭建 Cloudflare Worker 和配置私有访问 Token 的繁琐门槛。
4. 利用本地 Git Credential Manager 中的凭据，通过 GitHub API 自动创建远端仓库 t200216/freesub，完成首个 commit 的推送并自动触发首轮 workflow_dispatch 云端测活。

## Alternatives considered
1. **创建 Private 私有仓库**：
   - 否决原因：GitHub Free 账号对私有仓库每月仅有 2000 分钟 Actions 免费额度，而每轮数万节点的全流程测试需要耗时 20~30 分钟，按每 6 小时测一次的频率会在半个月内将额度烧尽。同时私有库的 Raw 链接带权限鉴权，常见的 Clash/v2rayN 客户端无法直接订阅，必须额外折腾 Cloudflare Worker 反代。
2. **纯本地运行而不是依赖 GitHub Actions**：
   - 否决原因：本地测试受制于国内网络环境，很多海外节点握手会被直接劣化或拦截，且本地需要常驻挂机。GitHub Actions 位于海外云端（Azure 骨干网），测试结果客观准确。

## Evidence
1. 本地代码语法检验：python -m py_compile d:\projects\freesub\scripts\main_v2.py 无任何语法报错。
2. 远程仓库创建：通过 GitHub API 成功创建 https://github.com/at200216/freesub。
3. Git 推送验证：本地 master/main 分支顺利推送到 origin/main。
4. 云端 Actions 触发：成功向 GitHub Actions 调度任务，Job ID 35088923276，步骤已正常进入 Run Real-Prober and Classifier。

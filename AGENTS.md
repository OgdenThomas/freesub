# freesub 项目规范

## 定位与说明
免费节点自动测活订阅池。定期（GitHub Actions）抓取公开节点源，通过 sing-box 内核建立实际代理隧道进行真测活、过滤断流与劫持，按家宽/机房及国家分类导出 Clash / v2rayN / sing-box 订阅。

## 运行与验证
- 云端运行：GitHub Actions `.github/workflows/update.yml`（每 6 小时或手动 dispatch）。
- 本地调试：`python -X utf8 scripts/main_v2.py`
- 依赖安装：`pip install -r scripts/requirements.txt`

## 关键目录与文件
- `scripts/main_v2.py`: 核心探测与订阅生成脚本
- `scripts/requirements.txt`: Python 依赖
- `.github/workflows/update.yml`: GitHub Actions 工作流
- `output/`: 测活结果订阅文件输出目录（由 Actions 自动提交）
- `README.md`: 包含订阅链接与统计表格的主文档（由脚本自动生成覆盖）

## 红线
- 不要在脚本中硬编码个人敏感 Token 或密码。
- 修改 `scripts/main_v2.py` 时保持输出格式与兼容性。

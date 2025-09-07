# Cloudflare Workers 网络粘贴板

一个基于 Cloudflare Workers 的现代化网络粘贴板应用，支持多文档管理、分享功能和密码保护。

## 功能特性

### 🔐 安全认证
- 服务端密码验证，确保安全性
- 会话管理，24小时免重复登录
- 所有敏感操作均在后端验证

### 📝 文档管理
- 创建、编辑、删除多个文档
- 支持自定义过期时间（1天、7天、30天、永久）
- 实时保存，支持 Ctrl+S 快捷键
- 文档元数据跟踪（创建时间、更新时间、查看次数等）

### 🔗 分享功能
- 直接分享文档访问链接
- 支持密码保护的文档分享
- 一键复制分享链接和文档内容
- 分享链接遵循原文档的权限设置

### 🎨 现代化界面
- 使用 Tailwind CSS 构建
- 响应式设计，支持移动设备
- 简洁美观的用户界面
- 良好的用户体验

## 技术架构

- **后端**: Cloudflare Workers (JavaScript)
- **存储**: Cloudflare KV
- **前端**: 原生 JavaScript + Tailwind CSS
- **架构**: 单文件脚本，前后端代码统一

## 部署指南

### 1. 准备工作

确保您已安装 Wrangler CLI：
```bash
npm install -g wrangler
```

### 2. 登录 Cloudflare
```bash
wrangler login
```

### 3. 创建 KV 命名空间
```bash
# 创建生产环境 KV 命名空间
wrangler kv:namespace create "NOTEPAD_KV"

# 创建预览环境 KV 命名空间
wrangler kv:namespace create "NOTEPAD_KV" --preview
```

### 4. 配置 wrangler.toml

将创建的 KV 命名空间 ID 填入 `wrangler.toml` 文件：

```toml
[[kv_namespaces]]
binding = "NOTEPAD_KV"
id = "your-production-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"
```

### 5. 设置管理员密码 🔐

**⚠️ 重要安全提醒：** 本项目不提供默认密码，您必须手动设置管理员密码。

#### 生产环境（推荐）：
```bash
# 使用 Cloudflare Workers Secrets 安全设置密码
wrangler secret put ADMIN_PASSWORD
# 按提示输入您的安全密码
```

#### 开发环境：
在 `wrangler.toml` 中临时设置（不要提交到版本控制）：
```toml
[vars]
ADMIN_PASSWORD = "your-development-password"
```

**详细配置说明请参考 [DEPLOYMENT.md](./DEPLOYMENT.md)**

### 6. 部署应用
```bash
# 部署到生产环境
wrangler deploy

# 或者先在预览环境测试
wrangler dev
```

## 使用说明

### 首次访问
1. 访问您的 Worker 域名
2. 输入设置的密码进行登录
3. 登录成功后可以开始创建和管理文档

### 创建文档
1. 点击"创建新文档"按钮
2. 输入文档标题
3. 选择过期时间
4. 点击"创建"进入编辑页面

### 编辑文档
1. 在文档列表中点击"编辑"按钮
2. 修改标题和内容
3. 使用"保存"按钮或 Ctrl+S 保存更改

### 分享文档
1. 在文档列表中点击"分享"按钮
2. 系统会复制文档的直接访问链接
3. 分享链接会遵循原文档的权限设置
4. 如果文档有密码保护，访问者需要输入密码

### 文档管理
- 查看文档的创建时间、更新时间、查看次数
- 设置文档过期时间，系统会自动清理过期文档
- 删除不需要的文档

## 安全注意事项

1. **修改默认密码**: 部署前务必修改 `CONFIG.PASSWORD` 为强密码
2. **HTTPS 访问**: Cloudflare Workers 默认支持 HTTPS
3. **会话管理**: 会话令牌存储在 localStorage 和 Cookie 中
4. **后端验证**: 所有敏感操作都在服务端验证
5. **隐私保护**:
   - 实际的 `wrangler.toml` 文件已添加到 `.gitignore`
   - 使用 `wrangler.example.toml` 作为配置模板
   - 密码等敏感信息不会上传到 GitHub

## GitHub 上传注意事项

### 隐私保护措施
- ✅ `wrangler.toml` 已添加到 `.gitignore`，不会上传实际配置
- ✅ 提供 `wrangler.example.toml` 作为配置模板
- ✅ 默认密码已设置为示例密码，需要用户自行修改
- ✅ 不包含任何真实的 KV 命名空间 ID 或 API 密钥

### 上传前检查清单
1. 确认 `.gitignore` 文件存在
2. 确认 `wrangler.toml` 不在版本控制中
3. 确认代码中没有硬编码的敏感信息
4. 在 README 中提醒用户修改密码和配置

## 自定义配置

### 修改会话时长
```javascript
const CONFIG = {
  SESSION_DURATION: 24 * 60 * 60 * 1000, // 24小时，可自定义
  // ...
};
```

### 修改默认过期时间
```javascript
const CONFIG = {
  DEFAULT_EXPIRY: 7 * 24 * 60 * 60 * 1000, // 7天，可自定义
  // ...
};
```

## 故障排除

### KV 命名空间错误
确保 `wrangler.toml` 中的 KV 命名空间 ID 正确配置。

### 密码验证失败
检查 `worker.js` 中的 `CONFIG.PASSWORD` 设置。

### 分享链接无法访问
确保文档设置了自定义名称，只有设置了自定义名称的文档才能生成分享链接。

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

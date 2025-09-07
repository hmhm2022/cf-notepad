
/**
 * Cloudflare Workers 网络粘贴板 - 修复版本
 * 使用模板字符串避免复杂的字符串拼接问题
 */

// 配置常量
const CONFIG = {
  PASSWORD: 'CloudflareNotepad2024!',
  SESSION_DURATION: 24 * 60 * 60 * 1000,
  DEFAULT_EXPIRY: 7 * 24 * 60 * 60 * 1000,
  DOC_SESSION_DURATION: 60 * 60 * 1000, // 文档访问会话1小时
  MAX_LOGIN_ATTEMPTS: 5, // 每小时最大尝试次数
  ATTEMPT_WINDOW: 60 * 60 * 1000, // 尝试次数重置窗口1小时
};

// ==================== 权限模型定义 ====================

// 用户类型定义
const PERMISSION_TYPES = {
  ADMIN: 'admin',      // 管理员：可操作所有文档
  GUEST: 'guest'       // 访客：只能访问有权限的文档
};

// 文档访问级别
const DOC_ACCESS_LEVELS = {
  PUBLIC_READ: 'public_read',       // 公开只读
  PUBLIC_WRITE: 'public_write',     // 公开可编辑
  PASSWORD_READ: 'password_read',   // 密码保护只读
  PASSWORD_WRITE: 'password_write', // 密码保护可编辑
  PRIVATE: 'private'                // 仅管理员可访问
};

// 用户权限级别
const PERMISSION_LEVELS = {
  READ: 'read',
  WRITE: 'write',
  ADMIN: 'admin'
};

// 会话配置
const SESSION_CONFIG = {
  ADMIN_DURATION: 24 * 60 * 60 * 1000,    // 管理员会话24小时
  GUEST_DURATION: 60 * 60 * 1000,         // 访客会话1小时
};

// 工具函数
function generateId() {
  // 使用更安全的随机ID生成
  return generateSecureId(24);
}

function generateShareToken() {
  return 'share_' + generateSecureId(12);
}

function isValidSession(sessionData) {
  if (!sessionData) return false;
  const session = safeJsonParse(sessionData);
  if (!session || !session.timestamp) return false;
  return Date.now() - session.timestamp < CONFIG.SESSION_DURATION;
}

// 验证文档名称格式
function isValidDocName(name) {
  const validation = validateInput(name, 'docName');
  return validation.valid;
}

// 密码哈希函数
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 获取客户端IP
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For') ||
         'unknown';
}

// 检查登录尝试次数
async function checkLoginAttempts(ip, docId) {
  const key = `attempts_${docId}_${ip}`;
  const attemptsData = await NOTEPAD_KV.get(key);

  if (!attemptsData) return true;

  const attempts = safeJsonParse(attemptsData, { timestamps: [] });
  const now = Date.now();

  // 清理过期的尝试记录
  if (attempts.timestamps && Array.isArray(attempts.timestamps)) {
    attempts.timestamps = attempts.timestamps.filter(
      timestamp => now - timestamp < CONFIG.ATTEMPT_WINDOW
    );
  } else {
    attempts.timestamps = [];
  }

  return attempts.timestamps.length < CONFIG.MAX_LOGIN_ATTEMPTS;
}

// 记录登录尝试
async function recordLoginAttempt(ip, docId) {
  const key = `attempts_${docId}_${ip}`;
  const attemptsData = await NOTEPAD_KV.get(key);
  const now = Date.now();

  let attempts;
  if (attemptsData) {
    attempts = safeJsonParse(attemptsData, { timestamps: [] });
    // 清理过期的尝试记录
    if (attempts.timestamps && Array.isArray(attempts.timestamps)) {
      attempts.timestamps = attempts.timestamps.filter(
        timestamp => now - timestamp < CONFIG.ATTEMPT_WINDOW
      );
    } else {
      attempts.timestamps = [];
    }
  } else {
    attempts = { timestamps: [] };
  }

  attempts.timestamps.push(now);

  await NOTEPAD_KV.put(key, JSON.stringify(attempts), {
    expirationTtl: CONFIG.ATTEMPT_WINDOW / 1000
  });
}

// ==================== 字符串处理安全函数 ====================

// HTML转义函数，防止XSS攻击
function escapeHtml(text) {
  if (typeof text !== 'string') {
    return '';
  }

  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
  };

  return text.replace(/[&<>"'`=\/]/g, function(s) {
    return map[s];
  });
}

// JavaScript字符串转义函数，防止JavaScript语法错误
function escapeJavaScript(text) {
  if (typeof text !== 'string') {
    return '';
  }

  const map = {
    '\\': '\\\\',
    '"': '\\"',
    "'": "\\'",
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
    '\b': '\\b',
    '\f': '\\f',
    '\v': '\\v',
    '\0': '\\0',
    '`': '\\`'
  };

  return text.replace(/[\\"'\n\r\t\b\f\v\0`]/g, function(s) {
    return map[s];
  });
}

// 输入验证函数
function validateInput(input, type, options = {}) {
  if (typeof input !== 'string') {
    return { valid: false, error: 'Input must be a string' };
  }

  const maxLength = options.maxLength || 10000;
  const minLength = options.minLength || 0;
  const allowEmpty = options.allowEmpty || false;

  // 长度检查
  if (!allowEmpty && input.length === 0) {
    return { valid: false, error: 'Input cannot be empty' };
  }

  if (input.length < minLength) {
    return { valid: false, error: `Input must be at least ${minLength} characters` };

  }

  if (input.length > maxLength) {
    return { valid: false, error: `Input must not exceed ${maxLength} characters` };
  }

  // 根据类型进行特定验证
  switch (type) {
    case 'docName':
      if (!/^[a-zA-Z0-9_-]{3,50}$/.test(input)) {
        return { valid: false, error: 'Document name must be 3-50 characters and contain only letters, numbers, hyphens, and underscores' };
      }
      break;

    case 'title':
      // 标题允许更多字符，但限制长度和危险字符
      if (input.length > 200) {
        return { valid: false, error: 'Title must not exceed 200 characters' };
      }
      // 检查是否包含控制字符
      if (/[\x00-\x1F\x7F]/.test(input)) {
        return { valid: false, error: 'Title contains invalid characters' };
      }
      break;

    case 'content':
      // 内容允许大部分字符，但限制长度
      if (input.length > 1000000) { // 1MB限制
        return { valid: false, error: 'Content must not exceed 1MB' };
      }
      break;

    case 'password':
      if (input.length < 1) {
        return { valid: false, error: 'Password cannot be empty' };
      }
      if (input.length > 128) {
        return { valid: false, error: 'Password must not exceed 128 characters' };
      }
      break;

    default:
      // 默认验证：检查控制字符
      if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(input)) {
        return { valid: false, error: 'Input contains invalid characters' };
      }
  }

  return { valid: true };
}

// 清理和标准化输入
function sanitizeInput(input, type) {
  if (typeof input !== 'string') {
    return '';
  }

  // 移除前后空白
  let cleaned = input.trim();

  switch (type) {
    case 'docName':
      // 文档名称只保留允许的字符
      cleaned = cleaned.replace(/[^a-zA-Z0-9_-]/g, '');
      break;

    case 'title':
      // 标题移除控制字符但保留其他字符
      cleaned = cleaned.replace(/[\x00-\x1F\x7F]/g, '');
      break;

    case 'content':
      // 内容保持原样，只移除null字符
      cleaned = cleaned.replace(/\x00/g, '');
      break;

    default:
      // 默认清理：移除控制字符
      cleaned = cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  }

  return cleaned;
}

// 安全的JSON解析
function safeJsonParse(jsonString, defaultValue = null) {
  try {
    if (typeof jsonString !== 'string') {
      return defaultValue;
    }

    // 检查JSON字符串长度
    if (jsonString.length > 10000000) { // 10MB限制
      throw new Error('JSON string too large');
    }

    return JSON.parse(jsonString);
  } catch (error) {
    console.error('JSON parse error:', error);
    return defaultValue;
  }
}

// 生成安全的随机ID
function generateSecureId(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';

  // 使用crypto.getRandomValues生成更安全的随机数
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);

  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }

  return result;
}

// ==================== 权限管理函数 ====================

// 创建会话
function createSession(type, permissions = {}) {
  return {
    type,
    timestamp: Date.now(),
    permissions: {
      admin: type === PERMISSION_TYPES.ADMIN,
      documents: permissions.documents || []  // 访客模式下可访问的文档ID列表
    }
  };
}

// 统一会话验证
async function validateSession(request, requiredType = null) {
  const sessionToken = request.headers.get('X-Session-Token') ||
                      getCookieValue(request.headers.get('Cookie'), 'sessionToken');

  if (!sessionToken) return null;

  const sessionData = await NOTEPAD_KV.get('session_' + sessionToken);
  if (!sessionData) return null;

  const session = safeJsonParse(sessionData);
  if (!session || !session.timestamp) return null;

  const duration = session.type === PERMISSION_TYPES.ADMIN ?
                   SESSION_CONFIG.ADMIN_DURATION :
                   SESSION_CONFIG.GUEST_DURATION;

  // 检查会话是否过期
  if (Date.now() - session.timestamp > duration) {
    await NOTEPAD_KV.delete('session_' + sessionToken);
    return null;
  }

  // 检查权限类型
  if (requiredType && session.type !== requiredType) {
    return null;
  }

  return session;
}

// 检查用户对文档的具体权限
async function getDocumentPermission(session, document) {
  // 管理员拥有所有权限
  if (session && session.permissions && session.permissions.admin) {
    return PERMISSION_LEVELS.ADMIN;
  }

  // 根据文档访问级别判断权限
  switch (document.accessLevel) {
    case DOC_ACCESS_LEVELS.PUBLIC_READ:
      return PERMISSION_LEVELS.READ;

    case DOC_ACCESS_LEVELS.PUBLIC_WRITE:
      return PERMISSION_LEVELS.WRITE;

    case DOC_ACCESS_LEVELS.PASSWORD_READ:
    case DOC_ACCESS_LEVELS.PASSWORD_WRITE:
      if (session && session.permissions && session.permissions.documents &&
          session.permissions.documents.includes(document.id)) {
        return document.accessLevel === DOC_ACCESS_LEVELS.PASSWORD_READ ?
               PERMISSION_LEVELS.READ : PERMISSION_LEVELS.WRITE;
      }
      return null;

    case DOC_ACCESS_LEVELS.PRIVATE:
      return null;

    default:
      // 兼容旧版本：如果没有设置访问级别，根据是否有密码判断
      if (document.password) {
        if (session && session.permissions && session.permissions.documents &&
            session.permissions.documents.includes(document.id)) {
          return PERMISSION_LEVELS.READ;
        }
        return null;
      } else {
        return PERMISSION_LEVELS.READ;
      }
  }
}

// 权限检查辅助函数
function canRead(permission) {
  return permission && [PERMISSION_LEVELS.READ, PERMISSION_LEVELS.WRITE, PERMISSION_LEVELS.ADMIN].includes(permission);
}

function canWrite(permission) {
  return permission && [PERMISSION_LEVELS.WRITE, PERMISSION_LEVELS.ADMIN].includes(permission);
}

function canAdmin(permission) {
  return permission === PERMISSION_LEVELS.ADMIN;
}

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 静态资源路由
  if (path === '/' || path === '/index.html') {
    return new Response(getMainHTML(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  // API 路由
  if (path.startsWith('/api/')) {
    return handleAPI(request, path, method);
  }

  // 分享链接路由
  if (path.startsWith('/share/')) {
    const shareToken = path.split('/')[2];
    return handleShareView(shareToken);
  }

  // 文档编辑路由
  if (path.startsWith('/edit/')) {
    const docId = path.split('/')[2];
    return handleEditView(docId, request);
  }

  // 直接文档访问路由 - 放在最后以避免与其他路由冲突
  if (path.length > 1 && !path.includes('.')) {
    const docName = path.substring(1); // 移除开头的 '/'
    if (isValidDocName(docName)) {
      return handleDirectDocAccess(docName, request);
    }
  }

  return new Response(get404HTML(), {
    status: 404,
    headers: { 'Content-Type': 'text/html' }
  });
}

// API 处理函数 - 重构版本
async function handleAPI(request, path, method) {
  // 根据路径前缀分发到不同的处理器
  if (path.startsWith('/api/auth/')) {
    return handleAuthAPI(request, path, method);
  }

  if (path.startsWith('/api/admin/')) {
    return handleAdminAPI(request, path, method);
  }

  if (path.startsWith('/api/public/')) {
    return handlePublicAPI(request, path, method);
  }

  // 兼容旧版本API路由
  return handleLegacyAPI(request, path, method);
}

// 认证相关API处理（无需权限验证）
async function handleAuthAPI(request, path, method) {
  if (path === '/api/auth/login' && method === 'POST') {
    return handleLogin(request);
  }

  if (path.startsWith('/api/auth/verify-doc/') && method === 'POST') {
    const docName = path.split('/')[4];
    return handleVerifyDocPassword(docName, request);
  }

  return new Response(JSON.stringify({ error: 'API not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 管理员API处理（需要管理员权限）
async function handleAdminAPI(request, path, method) {
  // 验证管理员会话
  const session = await validateSession(request, PERMISSION_TYPES.ADMIN);
  if (!session) {
    return new Response(JSON.stringify({ error: 'Admin access required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 文档管理API
  if (path === '/api/admin/documents' && method === 'GET') {
    return handleGetDocuments();
  }

  if (path === '/api/admin/documents' && method === 'POST') {
    return handleCreateDocument(request);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'GET') {
    const docId = path.split('/')[4];
    return handleGetDocument(docId);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'PUT') {
    const docId = path.split('/')[4];
    return handleUpdateDocument(docId, request);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'DELETE') {
    const docId = path.split('/')[4];
    return handleDeleteDocument(docId);
  }

  if (path.startsWith('/api/admin/documents/') && path.endsWith('/share') && method === 'POST') {
    const docId = path.split('/')[4];
    return handleCreateShare(docId);
  }

  return new Response(JSON.stringify({ error: 'API not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 公开API处理（根据文档权限验证）
async function handlePublicAPI(request, path, method) {
  if (path.startsWith('/api/public/doc/') && method === 'GET') {
    const docName = path.split('/')[4];
    return handleGetDocByName(docName, request);
  }

  if (path.startsWith('/api/public/share/') && method === 'GET') {
    const shareToken = path.split('/')[4];
    return handleGetSharedDoc(shareToken, request);
  }

  if (path.startsWith('/api/public/documents/') && method === 'PUT') {
    const docName = path.split('/')[4];
    return handleUpdateDocumentByName(docName, request);
  }

  return new Response(JSON.stringify({ error: 'API not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 兼容旧版本API路由
async function handleLegacyAPI(request, path, method) {
  // 登录接口重定向到新API
  if (path === '/api/login' && method === 'POST') {
    return handleAuthAPI(request, '/api/auth/login', method);
  }

  // 分享接口重定向到新API
  if (path.startsWith('/api/share/') && method === 'GET') {
    const shareToken = path.split('/')[3];
    return handlePublicAPI(request, `/api/public/share/${shareToken}`, method);
  }

  // 文档直接访问API重定向到新API
  if (path.startsWith('/api/doc/') && method === 'GET') {
    const docName = path.split('/')[3];
    return handlePublicAPI(request, `/api/public/doc/${docName}`, method);
  }

  if (path.startsWith('/api/doc/') && path.endsWith('/verify') && method === 'POST') {
    const docName = path.split('/')[3];
    return handleAuthAPI(request, `/api/auth/verify-doc/${docName}`, method);
  }

  // 管理员API重定向到新API
  if (path.startsWith('/api/documents')) {
    const newPath = path.replace('/api/documents', '/api/admin/documents');
    return handleAdminAPI(request, newPath, method);
  }

  return new Response(JSON.stringify({ error: 'API not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 登录处理
async function handleLogin(request) {
  try {
    const requestData = await request.json();
    const { password } = requestData;
    const ip = getClientIP(request);

    // 输入验证
    const passwordValidation = validateInput(password, 'password');
    if (!passwordValidation.valid) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Invalid input'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 检查管理员登录尝试次数
    const canAttempt = await checkLoginAttempts(ip, 'admin');
    if (!canAttempt) {
      return new Response(JSON.stringify({
        success: false,
        error: '尝试次数过多，请稍后再试'
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (password === CONFIG.PASSWORD) {
      const sessionToken = generateId();
      const sessionData = createSession(PERMISSION_TYPES.ADMIN);

      await NOTEPAD_KV.put('session_' + sessionToken, JSON.stringify(sessionData), {
        expirationTtl: SESSION_CONFIG.ADMIN_DURATION / 1000
      });

      return new Response(JSON.stringify({
        success: true,
        sessionToken: sessionToken
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 记录失败的登录尝试
    await recordLoginAttempt(ip, 'admin');

    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid credentials'
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Invalid request'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 获取文档列表
async function handleGetDocuments() {
  const list = await NOTEPAD_KV.list({ prefix: 'doc_' });
  const documents = [];

  for (const key of list.keys) {
    const docData = await NOTEPAD_KV.get(key.name);
    if (docData) {
      const doc = safeJsonParse(docData);
      if (doc && doc.id) {
        documents.push({
          id: doc.id,
          title: escapeHtml(doc.title || 'Untitled'),
          createdAt: doc.createdAt,
          updatedAt: doc.updatedAt,
          viewCount: doc.viewCount || 0,
          expiresAt: doc.expiresAt,
          hasPassword: !!doc.password,
          name: doc.name
        });
      }
    }
  }

  // 按更新时间倒序排列
  documents.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));

  return new Response(JSON.stringify(documents), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 创建文档
async function handleCreateDocument(request) {
  try {
    const requestData = await request.json();
    const { title, content, expiryDays, customName, password, accessLevel } = requestData;

    // 调试信息
    console.log('Create document request:', {
      title: `"${title}" (length: ${title?.length})`,
      content: `"${content}" (length: ${content?.length})`,
      expiryDays,
      customName: `"${customName}" (length: ${customName?.length})`,
      password: password ? `"${password}" (length: ${password.length})` : undefined,
      accessLevel
    });

    // 输入验证
    if (title !== undefined) {
      console.log('Validating title:', `"${title}"`);
      const titleValidation = validateInput(title, 'title', { allowEmpty: true });
      if (!titleValidation.valid) {
        console.log('Title validation failed:', titleValidation.error);
        return new Response(JSON.stringify({
          error: titleValidation.error
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (content !== undefined) {
      console.log('Validating content:', `"${content}"`);
      const contentValidation = validateInput(content, 'content', { allowEmpty: true });
      if (!contentValidation.valid) {
        console.log('Content validation failed:', contentValidation.error);
        return new Response(JSON.stringify({
          error: contentValidation.error
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (password !== undefined && password !== '') {
      console.log('Validating password:', `"${password}"`);
      const passwordValidation = validateInput(password, 'password');
      if (!passwordValidation.valid) {
        console.log('Password validation failed:', passwordValidation.error);
        return new Response(JSON.stringify({
          error: passwordValidation.error
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 验证过期天数
    if (expiryDays !== undefined && expiryDays !== -1) {
      if (typeof expiryDays !== 'number' || expiryDays < 1 || expiryDays > 365) {
        return new Response(JSON.stringify({
          error: 'Expiry days must be between 1 and 365, or -1 for no expiry'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 验证访问级别
    if (accessLevel !== undefined) {
      const validAccessLevels = Object.values(DOC_ACCESS_LEVELS);
      if (!validAccessLevels.includes(accessLevel)) {
        return new Response(JSON.stringify({
          error: 'Invalid access level'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 验证自定义名称
    if (customName) {
      console.log('Validating customName:', `"${customName}"`);
      const nameValidation = validateInput(customName, 'docName');
      if (!nameValidation.valid) {
        console.log('CustomName validation failed:', nameValidation.error);
        return new Response(JSON.stringify({
          error: nameValidation.error
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 检查名称是否已存在
      const existingMapping = await NOTEPAD_KV.get('name_' + customName);
      if (existingMapping) {
        return new Response(JSON.stringify({
          error: '文档名称已存在，请选择其他名称'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    const docId = generateId();
    const now = Date.now();
    const expiryTime = expiryDays === -1 ? null : now + (expiryDays * 24 * 60 * 60 * 1000);

    // 确定访问级别
    let finalAccessLevel = accessLevel;
    if (!finalAccessLevel) {
      // 兼容旧版本：根据密码自动确定访问级别
      if (password) {
        finalAccessLevel = DOC_ACCESS_LEVELS.PASSWORD_READ;
      } else {
        finalAccessLevel = DOC_ACCESS_LEVELS.PUBLIC_READ;
      }
    }

    const document = {
      id: docId,
      name: customName || null,
      title: sanitizeInput(title || 'Untitled', 'title'),
      content: sanitizeInput(content || '', 'content'),
      password: password ? await hashPassword(password) : null,
      accessLevel: finalAccessLevel,
      createdAt: now,
      updatedAt: now,
      lastViewedAt: now,
      viewCount: 0,
      expiresAt: expiryTime
    };

    const ttl = expiryTime ? Math.floor((expiryTime - now) / 1000) : undefined;
    const kvOptions = ttl ? { expirationTtl: ttl } : {};

    // 保存文档
    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document), kvOptions);

    // 如果有自定义名称，创建名称到ID的映射
    if (customName) {
      await NOTEPAD_KV.put('name_' + customName, docId, kvOptions);
    }

    return new Response(JSON.stringify(document), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Create document error:', error);
    return new Response(JSON.stringify({
      error: 'Invalid request'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 获取单个文档
async function handleGetDocument(docId) {
  const docData = await NOTEPAD_KV.get('doc_' + docId);
  if (!docData) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const document = JSON.parse(docData);
  document.viewCount++;
  document.lastViewedAt = Date.now();
  
  await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));
  
  return new Response(JSON.stringify(document), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 更新文档
async function handleUpdateDocument(docId, request) {
  const { title, content } = await request.json();
  const docData = await NOTEPAD_KV.get('doc_' + docId);
  
  if (!docData) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const document = JSON.parse(docData);
  document.title = title || document.title;
  document.content = content !== undefined ? content : document.content;
  document.updatedAt = Date.now();
  
  await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));
  
  return new Response(JSON.stringify(document), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 通过文档名称更新文档（用于直接编辑功能）
async function handleUpdateDocumentByName(docName, request) {
  try {
    const requestText = await request.text();
    console.log('Update document request text:', requestText);

    const parsedData = safeJsonParse(requestText);
    console.log('Parsed data:', parsedData);

    if (!parsedData) {
      return new Response(JSON.stringify({ error: 'Invalid JSON data' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { title, content } = parsedData;

    // 验证输入
    const titleValidation = validateInput(title, 'title');
    const contentValidation = validateInput(content, 'content', { allowEmpty: true });

    if (!titleValidation.valid) {
      return new Response(JSON.stringify({ error: titleValidation.error || 'Invalid title' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!contentValidation.valid) {
      return new Response(JSON.stringify({ error: contentValidation.error || 'Invalid content' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 通过名称查找文档ID
    const docId = await NOTEPAD_KV.get('name_' + docName);
    if (!docId) {
      return new Response(JSON.stringify({ error: 'Document not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 获取文档数据
    const docData = await NOTEPAD_KV.get('doc_' + docId);
    if (!docData) {
      return new Response(JSON.stringify({ error: 'Document not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const document = JSON.parse(docData);

    // 验证用户权限
    const session = await validateSession(request);
    const permission = await getDocumentPermission(session, document);

    if (!canWrite(permission)) {
      return new Response(JSON.stringify({ error: 'Permission denied' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 更新文档
    document.title = sanitizeInput(title, 'title');
    document.content = sanitizeInput(content, 'content');
    document.updatedAt = Date.now();

    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));

    return new Response(JSON.stringify({
      success: true,
      document: {
        id: document.id,
        name: document.name,
        title: document.title,
        content: document.content,
        updatedAt: document.updatedAt
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid request data' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 删除文档
async function handleDeleteDocument(docId) {
  // 先获取文档数据，检查是否有自定义名称
  const docData = await NOTEPAD_KV.get('doc_' + docId);
  
  if (docData) {
    const document = JSON.parse(docData);
    
    // 如果有自定义名称，删除名称映射
    if (document.name) {
      await NOTEPAD_KV.delete('name_' + document.name);
    }
  }
  
  // 删除文档本身
  await NOTEPAD_KV.delete('doc_' + docId);
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 创建分享链接
async function handleCreateShare(docId) {
  const docData = await NOTEPAD_KV.get('doc_' + docId);
  if (!docData) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const shareToken = generateShareToken();
  const shareData = {
    docId: docId,
    createdAt: Date.now()
  };
  
  await NOTEPAD_KV.put('share_' + shareToken, JSON.stringify(shareData));
  
  return new Response(JSON.stringify({ 
    shareToken: shareToken,
    shareUrl: '/share/' + shareToken
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 获取分享的文档
async function handleGetSharedDoc(shareToken) {
  const shareData = await NOTEPAD_KV.get('share_' + shareToken);
  if (!shareData) {
    return new Response(JSON.stringify({ error: 'Share not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const share = JSON.parse(shareData);
  const docData = await NOTEPAD_KV.get('doc_' + share.docId);
  
  if (!docData) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const document = JSON.parse(docData);
  
  return new Response(JSON.stringify({
    title: document.title,
    content: document.content,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 通过名称获取文档（用于直接访问）
async function handleGetDocByName(docName, request) {
  const docId = await NOTEPAD_KV.get('name_' + docName);
  if (!docId) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const docData = await NOTEPAD_KV.get('doc_' + docId);
  if (!docData) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const document = safeJsonParse(docData);
  if (!document || !document.id) {
    return new Response(JSON.stringify({ error: 'Document not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 获取用户会话
  const session = await validateSession(request);

  // 检查文档权限
  const permission = await getDocumentPermission(session, document);

  // 返回文档信息
  const response = {
    id: document.id,
    name: document.name,
    title: escapeHtml(document.title || 'Untitled'),
    hasPassword: !!document.password,
    accessLevel: document.accessLevel,
    createdAt: document.createdAt,
    viewCount: document.viewCount || 0,
    canRead: canRead(permission),
    canWrite: canWrite(permission)
  };

  // 如果有读取权限，返回内容
  if (canRead(permission)) {
    response.content = document.content || '';

    // 更新访问统计
    document.viewCount = (document.viewCount || 0) + 1;
    document.lastViewedAt = Date.now();
    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));
  }

  return new Response(JSON.stringify(response), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 验证文档密码
async function handleVerifyDocPassword(docName, request) {
  const { password } = await request.json();
  const ip = getClientIP(request);

  const docId = await NOTEPAD_KV.get('name_' + docName);
  if (!docId) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 检查尝试次数
  const canAttempt = await checkLoginAttempts(ip, docId);
  if (!canAttempt) {
    return new Response(JSON.stringify({
      error: '尝试次数过多，请稍后再试'
    }), {
      status: 429,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const docData = await NOTEPAD_KV.get('doc_' + docId);
  if (!docData) {
    await recordLoginAttempt(ip, docId);
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const document = safeJsonParse(docData);
  if (!document || !document.id) {
    await recordLoginAttempt(ip, docId);
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (!document.password) {
    return new Response(JSON.stringify({ error: 'Document is not password protected' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const hashedPassword = await hashPassword(password);
  if (hashedPassword !== document.password) {
    await recordLoginAttempt(ip, docId);
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 密码正确，创建访客会话
  const sessionToken = generateId();
  const sessionData = createSession(PERMISSION_TYPES.GUEST, {
    documents: [docId]
  });

  await NOTEPAD_KV.put('session_' + sessionToken, JSON.stringify(sessionData), {
    expirationTtl: SESSION_CONFIG.GUEST_DURATION / 1000
  });

  // 更新访问统计
  document.viewCount = (document.viewCount || 0) + 1;
  document.lastViewedAt = Date.now();
  await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));

  return new Response(JSON.stringify({
    success: true,
    sessionToken: sessionToken,
    document: {
      id: document.id,
      name: document.name,
      title: escapeHtml(document.title || 'Untitled'),
      content: document.content || '',
      accessLevel: document.accessLevel,
      createdAt: document.createdAt,
      viewCount: document.viewCount
    }
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 直接文档访问处理
async function handleDirectDocAccess(docName, request) {
  // 获取文档信息
  const docId = await NOTEPAD_KV.get('name_' + docName);
  if (!docId) {
    return new Response(get404HTML(), {
      status: 404,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  const docData = await NOTEPAD_KV.get('doc_' + docId);
  if (!docData) {
    return new Response(get404HTML(), {
      status: 404,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  const document = safeJsonParse(docData);
  if (!document || !document.id) {
    return new Response(get404HTML(), {
      status: 404,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  // 使用统一的会话验证系统
  const session = await validateSession(request);
  const permission = await getDocumentPermission(session, document);

  // 如果有读取权限，直接显示文档
  if (canRead(permission)) {
    // 更新访问统计
    document.viewCount = (document.viewCount || 0) + 1;
    document.lastViewedAt = Date.now();
    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));

    return new Response(getDirectDocHTML(document, permission), {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  // 如果文档有密码保护且没有权限，显示密码输入页面
  if (document.password) {
    return new Response(getDocPasswordHTML(docName, document.title), {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  // 其他情况返回404
  return new Response(get404HTML(), {
    status: 404,
    headers: { 'Content-Type': 'text/html' }
  });
}

// 分享页面视图
async function handleShareView(shareToken) {
  return new Response(getShareHTML(shareToken), {
    headers: { 'Content-Type': 'text/html' }
  });
}

// 编辑页面视图
async function handleEditView(docId, request) {
  const sessionToken = getCookieValue(request.headers.get('Cookie'), 'sessionToken');
  const sessionData = sessionToken ? await NOTEPAD_KV.get('session_' + sessionToken) : null;
  
  if (!isValidSession(sessionData)) {
    return new Response(getMainHTML(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
  
  return new Response(getEditHTML(docId), {
    headers: { 'Content-Type': 'text/html' }
  });
}

function getCookieValue(cookieString, name) {
  if (!cookieString) return null;
  const match = cookieString.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

// HTML 页面生成函数
function getMainHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- 登录模态框 -->
    <div id="loginModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
            <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">登录验证</h2>
            <form id="loginForm">
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">密码</label>
                    <input type="password" id="passwordInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                </div>
                <button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    登录
                </button>
            </form>
            <div id="loginError" class="mt-4 text-red-500 text-sm hidden"></div>
        </div>
    </div>

    <!-- 主界面 -->
    <div id="mainApp" class="hidden">
        <header class="bg-white shadow-sm">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center py-6">
                    <h1 class="text-3xl font-bold text-gray-900">CF Notepad</h1>
                    <button id="logoutBtn" class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">
                        退出登录
                    </button>
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div class="px-4 py-6 sm:px-0">
                <!-- 创建新文档按钮 -->
                <div class="mb-6">
                    <button id="createDocBtn" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">
                        + 创建新文档
                    </button>
                </div>

                <!-- 文档列表 -->
                <div class="bg-white shadow overflow-hidden sm:rounded-md">
                    <div class="px-4 py-5 sm:p-6">
                        <h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">文档列表</h3>
                        <div id="documentsList" class="space-y-3">
                            <!-- 文档列表将在这里动态加载 -->
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- 创建文档模态框 -->
    <div id="createModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="bg-white rounded-lg p-8 max-w-lg w-full mx-4 max-h-screen overflow-y-auto">
            <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">创建新文档</h2>
            <form id="createForm">
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">文档标题</label>
                    <input type="text" id="titleInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                </div>

                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">
                        自定义文档名称
                        <span class="text-gray-500 font-normal">(可选，用于直接访问)</span>
                    </label>
                    <input type="text" id="customNameInput"
                           class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                           placeholder="例如: my-document (3-50个字符，仅限字母数字-_)">
                    <div class="text-xs text-gray-500 mt-1">
                        设置后可通过 域名/文档名称 直接访问
                    </div>
                </div>

                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">访问权限</label>
                    <select id="accessLevelSelect" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value="public_read">公开只读 - 任何人都可以查看，但不能编辑</option>
                        <option value="public_write">公开可编辑 - 任何人都可以查看和编辑</option>
                        <option value="password_read">密码保护只读 - 需要密码才能查看</option>
                        <option value="password_write">密码保护可编辑 - 需要密码才能查看和编辑</option>
                        <option value="private">私有 - 仅管理员可访问</option>
                    </select>
                    <div class="text-xs text-gray-500 mt-1">
                        选择文档的访问权限级别
                    </div>
                </div>

                <div class="mb-4" id="passwordSection" style="display: none;">
                    <label class="block text-gray-700 text-sm font-bold mb-2">
                        访问密码
                        <span class="text-red-500">*</span>
                    </label>
                    <input type="password" id="createPasswordInput"
                           class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                           placeholder="设置密码保护文档">
                    <div class="text-xs text-gray-500 mt-1">
                        密码保护文档需要设置访问密码
                    </div>
                </div>

                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-bold mb-2">过期时间</label>
                    <select id="expirySelect" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value="1">1天</option>
                        <option value="7" selected>7天</option>
                        <option value="30">30天</option>
                        <option value="-1">永久</option>
                    </select>
                </div>

                <div id="createError" class="mb-4 text-red-500 text-sm hidden"></div>

                <div class="flex space-x-4">
                    <button type="submit" class="flex-1 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                        创建
                    </button>
                    <button type="button" id="cancelCreateBtn" class="flex-1 bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        取消
                    </button>
                </div>
            </form>
        </div>
    </div>

    ${getMainScript()}
</body>
</html>`;
}

function getMainScript() {
  return `<script>
    let sessionToken = localStorage.getItem("sessionToken") || getCookie("sessionToken");

    function getCookie(name) {
        const value = "; " + document.cookie;
        const parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop().split(";").shift();
        return null;
    }

    function checkSession() {
        if (sessionToken) {
            document.getElementById("loginModal").classList.add("hidden");
            document.getElementById("mainApp").classList.remove("hidden");
            loadDocuments();
        } else {
            document.getElementById("loginModal").classList.remove("hidden");
            document.getElementById("mainApp").classList.add("hidden");
        }
    }

    async function apiCall(endpoint, options = {}) {
        const headers = {
            "Content-Type": "application/json",
            ...options.headers
        };

        if (sessionToken) {
            headers["X-Session-Token"] = sessionToken;
        }

        const response = await fetch(endpoint, {
            ...options,
            headers
        });

        if (response.status === 401) {
            sessionToken = null;
            localStorage.removeItem("sessionToken");
            document.cookie = "sessionToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
            checkSession();
            throw new Error("Session expired");
        }

        // 检查其他错误状态码
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(errorData.error || "HTTP " + response.status + ": " + response.statusText);
        }

        return response;
    }

    async function loadDocuments() {
        try {
            const response = await apiCall("/api/admin/documents");
            const documents = await response.json();

            const listElement = document.getElementById("documentsList");
            if (documents.length === 0) {
                listElement.innerHTML = '<p class="text-gray-500">暂无文档，点击上方按钮创建第一个文档</p>';
                return;
            }

            // HTML转义函数
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            listElement.innerHTML = documents.map(doc => {
                const createdDate = new Date(doc.createdAt).toLocaleString();
                const updatedDate = new Date(doc.updatedAt).toLocaleString();
                const expiryText = doc.expiresAt ? new Date(doc.expiresAt).toLocaleString() : "永久";
                const currentDomain = window.location.origin;

                let directAccessSection = '';
                if (doc.name) {
                    const passwordBadge = doc.hasPassword ? '<span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">🔒 密码保护</span>' : '';
                    directAccessSection = \`
                        <div class="mb-2">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                直接访问: \${escapeHtml(doc.name)}
                            </span>
                            \${passwordBadge}
                        </div>
                        <div class="mb-2">
                            <a href="/\${encodeURIComponent(doc.name)}" target="_blank" class="text-blue-600 hover:text-blue-800 text-sm underline">
                                \${currentDomain}/\${escapeHtml(doc.name)}
                            </a>
                            <button onclick="copyDirectLink('\${escapeJavaScript(doc.name)}')" class="ml-2 text-gray-500 hover:text-gray-700 text-xs">
                                📋 复制链接
                            </button>
                        </div>
                    \`;
                }

                return \`
                    <div class="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                        <div class="flex justify-between items-start">
                            <div class="flex-1">
                                <h4 class="text-lg font-medium text-gray-900 mb-2">\${escapeHtml(doc.title)}</h4>
                                \${directAccessSection}
                                <div class="text-sm text-gray-500 space-y-1">
                                    <p>创建时间: \${createdDate}</p>
                                    <p>更新时间: \${updatedDate}</p>
                                    <p>查看次数: \${doc.viewCount}</p>
                                    <p>过期时间: \${expiryText}</p>
                                </div>
                            </div>
                            <div class="flex space-x-2 ml-4">
                                <button onclick="editDocument('\${escapeJavaScript(doc.id)}')" class="bg-blue-500 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                                    编辑
                                </button>
                                <button onclick="shareDocument('\${escapeJavaScript(doc.id)}')" class="bg-green-500 hover:bg-green-700 text-white px-3 py-1 rounded text-sm">
                                    分享
                                </button>
                                <button onclick="deleteDocument('\${escapeJavaScript(doc.id)}')" class="bg-red-500 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
                                    删除
                                </button>
                            </div>
                        </div>
                    </div>
                \`;
            }).join("");
        } catch (error) {
            console.error("Failed to load documents:", error);
        }
    }

    function editDocument(docId) {
        window.location.href = "/edit/" + docId;
    }

    async function shareDocument(docId) {
        try {
            const response = await apiCall(\`/api/admin/documents/\${docId}/share\`, {
                method: "POST"
            });
            const result = await response.json();

            const shareUrl = window.location.origin + result.shareUrl;

            if (navigator.clipboard) {
                await navigator.clipboard.writeText(shareUrl);
                alert("分享链接已复制到剪贴板:\\n" + shareUrl);
            } else {
                prompt("分享链接（请手动复制）:", shareUrl);
            }
        } catch (error) {
            alert("创建分享链接失败: " + error.message);
        }
    }

    async function deleteDocument(docId) {
        if (!confirm("确定要删除这个文档吗？此操作不可撤销。")) {
            return;
        }

        try {
            await apiCall(\`/api/admin/documents/\${docId}\`, {
                method: "DELETE"
            });
            loadDocuments();
        } catch (error) {
            alert("删除失败: " + error.message);
        }
    }

    // 事件监听器
    document.getElementById("loginForm").addEventListener("submit", async function(e) {
        e.preventDefault();
        const password = document.getElementById("passwordInput").value;
        const errorDiv = document.getElementById("loginError");

        try {
            const response = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: password })
            });

            const result = await response.json();

            if (response.ok && result.success) {
                sessionToken = result.sessionToken;
                localStorage.setItem("sessionToken", sessionToken);
                document.cookie = "sessionToken=" + sessionToken + "; path=/; max-age=86400";
                errorDiv.classList.add("hidden");
                checkSession();
            } else {
                errorDiv.textContent = result.error || "密码错误，请重试";
                errorDiv.classList.remove("hidden");
            }
        } catch (error) {
            console.error("Login error:", error);
            errorDiv.textContent = "登录失败，请重试";
            errorDiv.classList.remove("hidden");
        }
    });

    document.getElementById("logoutBtn").addEventListener("click", function() {
        sessionToken = null;
        localStorage.removeItem("sessionToken");
        document.cookie = "sessionToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
        checkSession();
    });

    document.getElementById("createDocBtn").addEventListener("click", function() {
        document.getElementById("createModal").classList.remove("hidden");
    });

    document.getElementById("cancelCreateBtn").addEventListener("click", function() {
        document.getElementById("createModal").classList.add("hidden");
    });

    // 访问级别选择变化时，控制密码字段显示
    document.getElementById("accessLevelSelect").addEventListener("change", function() {
        const accessLevel = this.value;
        const passwordSection = document.getElementById("passwordSection");
        const passwordInput = document.getElementById("createPasswordInput");

        if (accessLevel === "password_read" || accessLevel === "password_write") {
            passwordSection.style.display = "block";
            passwordInput.required = true;
        } else {
            passwordSection.style.display = "none";
            passwordInput.required = false;
            passwordInput.value = "";
        }
    });

    document.getElementById("createForm").addEventListener("submit", async function(e) {
        e.preventDefault();
        const title = document.getElementById("titleInput").value;
        const customName = document.getElementById("customNameInput").value.trim();
        const password = document.getElementById("createPasswordInput").value;
        const accessLevel = document.getElementById("accessLevelSelect").value;
        const expiryDays = parseInt(document.getElementById("expirySelect").value);
        const errorDiv = document.getElementById("createError");

        // 隐藏之前的错误信息
        errorDiv.classList.add("hidden");

        // 验证自定义名称格式
        if (customName && !/^[a-zA-Z0-9_-]{3,50}$/.test(customName)) {
            errorDiv.textContent = "文档名称只能包含字母、数字、连字符和下划线，长度3-50字符";
            errorDiv.classList.remove("hidden");
            return;
        }

        // 验证密码保护文档必须设置密码
        if ((accessLevel === "password_read" || accessLevel === "password_write") && !password) {
            errorDiv.textContent = "密码保护文档必须设置访问密码";
            errorDiv.classList.remove("hidden");
            return;
        }

        try {
            const requestData = {
                title: title,
                content: "",
                expiryDays: expiryDays,
                accessLevel: accessLevel
            };

            if (customName) {
                requestData.customName = customName;
            }

            if (password) {
                requestData.password = password;
            }

            const response = await apiCall("/api/admin/documents", {
                method: "POST",
                body: JSON.stringify(requestData)
            });

            const newDoc = await response.json();

            // 清空表单
            document.getElementById("createModal").classList.add("hidden");
            document.getElementById("titleInput").value = "";
            document.getElementById("customNameInput").value = "";
            document.getElementById("createPasswordInput").value = "";
            document.getElementById("accessLevelSelect").value = "public_read";
            document.getElementById("passwordSection").style.display = "none";
            document.getElementById("expirySelect").value = "7";

            window.location.href = "/edit/" + newDoc.id;
        } catch (error) {
            const errorMessage = error.message;
            if (errorMessage.includes("文档名称已存在")) {
                errorDiv.textContent = "文档名称已存在，请选择其他名称";
                errorDiv.classList.remove("hidden");
            } else if (errorMessage.includes("文档名称只能包含")) {
                errorDiv.textContent = "文档名称格式不正确";
                errorDiv.classList.remove("hidden");
            } else {
                errorDiv.textContent = "创建文档失败: " + errorMessage;
                errorDiv.classList.remove("hidden");
            }
        }
    });

    // 复制直接访问链接
    function copyDirectLink(docName) {
        const url = window.location.origin + "/" + docName;

        if (navigator.clipboard) {
            navigator.clipboard.writeText(url).then(function() {
                alert("直接访问链接已复制到剪贴板");
            }).catch(function() {
                alert("复制失败，请手动复制: " + url);
            });
        } else {
            // 降级方案
            const textArea = document.createElement("textarea");
            textArea.value = url;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand("copy");
                alert("直接访问链接已复制到剪贴板");
            } catch (err) {
                alert("复制失败，请手动复制: " + url);
            }
            document.body.removeChild(textArea);
        }
    }

    // 初始化
    checkSession();
</script>`;
}

function getEditHTML(docId) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑文档 - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center py-6">
                <h1 class="text-3xl font-bold text-gray-900">编辑文档</h1>
                <div class="flex space-x-4">
                    <button id="saveBtn" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                        保存
                    </button>
                    <button id="shareBtn" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">
                        分享
                    </button>
                    <a href="/" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        返回
                    </a>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div class="px-4 py-6 sm:px-0">
            <div class="bg-white shadow overflow-hidden sm:rounded-md">
                <div class="px-4 py-5 sm:p-6">
                    <div class="mb-4">
                        <label class="block text-gray-700 text-sm font-bold mb-2">文档标题</label>
                        <input type="text" id="titleInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div class="mb-4">
                        <label class="block text-gray-700 text-sm font-bold mb-2">文档内容</label>
                        <textarea id="contentInput" rows="20" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"></textarea>
                    </div>
                    <div id="statusMessage" class="mt-4 text-sm hidden"></div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const docId = "${escapeJavaScript(docId)}";
        let sessionToken = localStorage.getItem("sessionToken") || getCookie("sessionToken");

        function getCookie(name) {
            const value = "; " + document.cookie;
            const parts = value.split("; " + name + "=");
            if (parts.length === 2) return parts.pop().split(";").shift();
            return null;
        }

        async function apiCall(endpoint, options = {}) {
            const headers = {
                "Content-Type": "application/json",
                ...options.headers
            };

            if (sessionToken) {
                headers["X-Session-Token"] = sessionToken;
            }

            const response = await fetch(endpoint, {
                ...options,
                headers
            });

            if (response.status === 401) {
                window.location.href = "/";
                return;
            }

            // 检查其他错误状态码
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
                throw new Error(errorData.error || "HTTP " + response.status + ": " + response.statusText);
            }

            return response;
        }

        async function loadDocument() {
            try {
                const response = await apiCall(\`/api/admin/documents/\${docId}\`);
                const docData = await response.json();

                document.getElementById("titleInput").value = docData.title;
                document.getElementById("contentInput").value = docData.content;
            } catch (error) {
                console.error("Failed to load document:", error);
                showMessage("加载文档失败", "error");
            }
        }

        async function saveDocument() {
            const title = document.getElementById("titleInput").value;
            const content = document.getElementById("contentInput").value;

            try {
                const response = await apiCall(\`/api/admin/documents/\${docId}\`, {
                    method: "PUT",
                    body: JSON.stringify({ title, content })
                });

                if (response.ok) {
                    showMessage("保存成功", "success");
                } else {
                    showMessage("保存失败", "error");
                }
            } catch (error) {
                console.error("Failed to save document:", error);
                showMessage("保存失败", "error");
            }
        }

        async function shareDocument() {
            try {
                const response = await apiCall(\`/api/admin/documents/\${docId}/share\`, {
                    method: "POST"
                });
                const result = await response.json();

                const shareUrl = window.location.origin + result.shareUrl;

                if (navigator.clipboard) {
                    await navigator.clipboard.writeText(shareUrl);
                    showMessage("分享链接已复制到剪贴板", "success");
                } else {
                    prompt("分享链接（请手动复制）:", shareUrl);
                }
            } catch (error) {
                showMessage("创建分享链接失败", "error");
            }
        }

        function showMessage(message, type) {
            const messageDiv = document.getElementById("statusMessage");
            messageDiv.textContent = message;
            messageDiv.className = \`mt-4 text-sm \${type === "success" ? "text-green-600" : "text-red-600"}\`;
            messageDiv.classList.remove("hidden");

            setTimeout(() => {
                messageDiv.classList.add("hidden");
            }, 3000);
        }

        // 事件监听器
        document.getElementById("saveBtn").addEventListener("click", saveDocument);
        document.getElementById("shareBtn").addEventListener("click", shareDocument);

        // 自动保存
        let saveTimeout;
        function autoSave() {
            clearTimeout(saveTimeout);
            saveTimeout = setTimeout(saveDocument, 2000);
        }

        document.getElementById("titleInput").addEventListener("input", autoSave);
        document.getElementById("contentInput").addEventListener("input", autoSave);

        // 快捷键
        document.addEventListener("keydown", function(e) {
            if (e.ctrlKey && e.key === "s") {
                e.preventDefault();
                saveDocument();
            }
        });

        // 初始化
        loadDocument();
    </script>
</body>
</html>`;
}

function getShareHTML(shareToken) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>分享文档 - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center py-6">
                <h1 class="text-3xl font-bold text-gray-900">分享文档</h1>
                <button id="copyBtn" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                    复制内容
                </button>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div class="px-4 py-6 sm:px-0">
            <div class="bg-white shadow overflow-hidden sm:rounded-md">
                <div class="px-4 py-5 sm:p-6">
                    <h3 id="documentTitle" class="text-lg leading-6 font-medium text-gray-900 mb-4">加载中...</h3>
                    <div id="documentContent" class="whitespace-pre-wrap font-mono text-sm bg-gray-50 p-4 rounded border">
                        加载中...
                    </div>
                    <div id="documentInfo" class="mt-4 text-sm text-gray-500">
                        <!-- 文档信息将在这里显示 -->
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const shareToken = "${escapeJavaScript(shareToken)}";

        async function loadSharedDocument() {
            try {
                const response = await fetch(\`/api/public/share/\${shareToken}\`);
                if (!response.ok) {
                    throw new Error("Document not found");
                }

                const docData = await response.json();

                document.getElementById("documentTitle").textContent = docData.title;
                document.getElementById("documentContent").textContent = docData.content;

                const createdDate = new Date(docData.createdAt).toLocaleString();
                const updatedDate = new Date(docData.updatedAt).toLocaleString();

                document.getElementById("documentInfo").innerHTML = \`
                    <p>创建时间: \${createdDate}</p>
                    <p>更新时间: \${updatedDate}</p>
                \`;
            } catch (error) {
                console.error("Failed to load shared document:", error);
                document.getElementById("documentTitle").textContent = "文档不存在";
                document.getElementById("documentContent").textContent = "抱歉，您访问的文档不存在或已过期。";
            }
        }

        function copyContent() {
            const content = document.getElementById("documentContent").textContent;

            if (navigator.clipboard) {
                navigator.clipboard.writeText(content).then(function() {
                    alert("内容已复制到剪贴板");
                }).catch(function() {
                    alert("复制失败，请手动选择并复制");
                });
            } else {
                // 降级方案
                const textArea = document.createElement("textarea");
                textArea.value = content;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand("copy");
                    alert("内容已复制到剪贴板");
                } catch (err) {
                    alert("复制失败，请手动选择并复制");
                }
                document.body.removeChild(textArea);
            }
        }

        // 绑定事件
        document.getElementById("copyBtn").addEventListener("click", copyContent);

        // 初始化
        loadSharedDocument();
    </script>
</body>
</html>`;
}

// 404错误页面
function get404HTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>页面未找到 - 云端粘贴板</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-white rounded-lg shadow-md p-8 text-center">
        <div class="mb-6">
            <div class="text-6xl text-gray-400 mb-4">404</div>
            <h1 class="text-2xl font-bold text-gray-800 mb-2">页面未找到</h1>
            <p class="text-gray-600">抱歉，您访问的文档不存在或已过期。</p>
        </div>
        <div class="space-y-3">
            <a href="/" class="block w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                返回首页
            </a>
        </div>
    </div>
</body>
</html>`;
}

// 文档密码输入页面
function getDocPasswordHTML(docName, docTitle) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问文档：${escapeHtml(docTitle)} - 云端粘贴板</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-white rounded-lg shadow-md p-8">
        <div class="text-center mb-6">
            <h1 class="text-2xl font-bold text-gray-800 mb-2">访问受保护的文档</h1>
            <p class="text-gray-600">${escapeHtml(docTitle)}</p>
        </div>

        <form id="passwordForm" class="space-y-4">
            <div>
                <label for="passwordInput" class="block text-sm font-medium text-gray-700 mb-2">
                    请输入文档密码
                </label>
                <input type="password" id="passwordInput"
                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                       placeholder="输入密码" required>
            </div>
            <button type="submit"
                    class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition duration-200">
                访问文档
            </button>
        </form>

        <div id="errorMessage" class="mt-4 text-red-500 text-sm hidden"></div>

        <div class="mt-6 text-center">
            <a href="/" class="text-blue-500 hover:text-blue-700 text-sm">返回首页</a>
        </div>
    </div>

    <script>
        document.getElementById("passwordForm").addEventListener("submit", async function(e) {
            e.preventDefault();

            const password = document.getElementById("passwordInput").value;
            const errorDiv = document.getElementById("errorMessage");
            const submitBtn = e.target.querySelector('button[type="submit"]');

            // 禁用提交按钮
            submitBtn.disabled = true;
            submitBtn.textContent = "验证中...";

            try {
                const response = await fetch(\`/api/auth/verify-doc/${encodeURIComponent(docName)}\`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password: password })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    // 设置统一的会话cookie
                    document.cookie = "sessionToken=" + result.sessionToken + "; path=/; max-age=3600";
                    // 重新加载页面以显示文档内容
                    window.location.reload();
                } else {
                    errorDiv.textContent = result.error || "密码错误，请重试";
                    errorDiv.classList.remove("hidden");
                    document.getElementById("passwordInput").value = "";
                    document.getElementById("passwordInput").focus();
                }
            } catch (error) {
                console.error("Verification error:", error);
                errorDiv.textContent = "验证失败，请重试";
                errorDiv.classList.remove("hidden");
            } finally {
                // 恢复提交按钮
                submitBtn.disabled = false;
                submitBtn.textContent = "访问文档";
            }
        });

        // 自动聚焦密码输入框
        document.getElementById("passwordInput").focus();
    </script>
</body>
</html>`;
}

// 直接文档显示页面
function getDirectDocHTML(document, permission) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(document.title)} - 云端粘贴板</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- 头部信息 -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                <div class="mb-4 sm:mb-0">
                    <h1 class="text-2xl font-bold text-gray-800 mb-2">${escapeHtml(document.title)}</h1>
                    <div class="text-sm text-gray-600 space-y-1">
                        ${document.name ? `<div>文档名称: <span class="font-medium">${escapeHtml(document.name)}</span></div>` : ''}
                        <div>创建时间: ${new Date(document.createdAt).toLocaleString('zh-CN')}</div>
                        <div>查看次数: ${document.viewCount}</div>
                    </div>
                </div>
                <div class="flex flex-col sm:flex-row gap-2">
                    ${canWrite(permission) ? `
                    <button id="editBtn"
                            class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                        编辑文档
                    </button>
                    <button id="saveBtn" style="display: none;"
                            class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                        保存
                    </button>
                    <button id="cancelBtn" style="display: none;"
                            class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                        取消
                    </button>
                    ` : ''}
                    <button id="copyBtn"
                            class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                        复制内容
                    </button>
                    <a href="/"
                       class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded text-center transition duration-200">
                        返回首页
                    </a>
                </div>
            </div>
        </div>

        <!-- 文档内容 -->
        <div class="bg-white rounded-lg shadow-md p-6">
            <div class="prose max-w-none">
                <!-- 查看模式 -->
                <pre id="documentContent" class="whitespace-pre-wrap font-mono text-sm bg-gray-50 p-4 rounded border overflow-x-auto">${escapeHtml(document.content)}</pre>

                <!-- 编辑模式 -->
                <div id="editMode" style="display: none;">
                    <div class="mb-4">
                        <label class="block text-gray-700 text-sm font-bold mb-2">文档标题</label>
                        <input type="text" id="titleInput" value="${escapeHtml(document.title)}"
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div class="mb-4">
                        <label class="block text-gray-700 text-sm font-bold mb-2">文档内容</label>
                        <textarea id="contentInput" rows="20"
                                  class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                                  placeholder="请输入文档内容...">${escapeHtml(document.content)}</textarea>
                    </div>
                </div>
            </div>
        </div>

        <!-- 页脚信息 -->
        <div class="mt-6 text-center text-gray-500 text-sm">
            <p>云端粘贴板 - 安全、便捷的文档分享平台</p>
        </div>
    </div>

    <script>
        function copyContent() {
            const content = document.getElementById("documentContent").textContent;

            if (navigator.clipboard) {
                navigator.clipboard.writeText(content).then(function() {
                    // 显示复制成功提示
                    const btn = document.getElementById("copyBtn");
                    const originalText = btn.textContent;
                    btn.textContent = "已复制!";
                    btn.classList.remove("bg-blue-500", "hover:bg-blue-700");
                    btn.classList.add("bg-green-500");

                    setTimeout(() => {
                        btn.textContent = originalText;
                        btn.classList.remove("bg-green-500");
                        btn.classList.add("bg-blue-500", "hover:bg-blue-700");
                    }, 2000);
                }).catch(function() {
                    alert("复制失败，请手动选择并复制");
                });
            } else {
                // 降级方案
                const textArea = document.createElement("textarea");
                textArea.value = content;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand("copy");
                    const btn = document.getElementById("copyBtn");
                    const originalText = btn.textContent;
                    btn.textContent = "已复制!";
                    btn.classList.remove("bg-blue-500", "hover:bg-blue-700");
                    btn.classList.add("bg-green-500");

                    setTimeout(() => {
                        btn.textContent = originalText;
                        btn.classList.remove("bg-green-500");
                        btn.classList.add("bg-blue-500", "hover:bg-blue-700");
                    }, 2000);
                } catch (err) {
                    alert("复制失败，请手动选择并复制");
                }
                document.body.removeChild(textArea);
            }
        }

        // 编辑功能
        let isEditing = false;
        let originalTitle = "${escapeJavaScript(document.title)}";
        let originalContent = "${escapeJavaScript(document.content)}";

        function enterEditMode() {
            isEditing = true;

            // 隐藏查看模式元素
            document.getElementById("documentContent").style.display = "none";
            document.getElementById("editBtn").style.display = "none";

            // 显示编辑模式元素
            document.getElementById("editMode").style.display = "block";
            document.getElementById("saveBtn").style.display = "inline-block";
            document.getElementById("cancelBtn").style.display = "inline-block";

            // 聚焦到内容输入框
            document.getElementById("contentInput").focus();
        }

        function exitEditMode() {
            isEditing = false;

            // 显示查看模式元素
            document.getElementById("documentContent").style.display = "block";
            document.getElementById("editBtn").style.display = "inline-block";

            // 隐藏编辑模式元素
            document.getElementById("editMode").style.display = "none";
            document.getElementById("saveBtn").style.display = "none";
            document.getElementById("cancelBtn").style.display = "none";
        }

        function cancelEdit() {
            // 恢复原始值
            document.getElementById("titleInput").value = originalTitle;
            document.getElementById("contentInput").value = originalContent;
            exitEditMode();
        }

        async function saveDocument() {
            const title = document.getElementById("titleInput").value.trim();
            const content = document.getElementById("contentInput").value;

            if (!title) {
                alert("请输入文档标题");
                return;
            }

            const saveBtn = document.getElementById("saveBtn");
            const originalText = saveBtn.textContent;
            saveBtn.textContent = "保存中...";
            saveBtn.disabled = true;

            try {
                // 获取当前会话token
                const sessionToken = getCookie("sessionToken");

                const response = await fetch(\`/api/public/documents/${encodeURIComponent(document.name || document.id)}\`, {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Session-Token": sessionToken
                    },
                    body: JSON.stringify({ title, content })
                });

                const result = await response.json();

                if (response.ok) {
                    // 更新页面显示
                    document.querySelector("h1").textContent = title;
                    document.getElementById("documentContent").textContent = content;

                    // 更新原始值
                    originalTitle = title;
                    originalContent = content;

                    exitEditMode();

                    // 显示成功提示
                    saveBtn.textContent = "已保存!";
                    saveBtn.classList.remove("bg-blue-500", "hover:bg-blue-700");
                    saveBtn.classList.add("bg-green-500");

                    setTimeout(() => {
                        saveBtn.textContent = originalText;
                        saveBtn.classList.remove("bg-green-500");
                        saveBtn.classList.add("bg-blue-500", "hover:bg-blue-700");
                        saveBtn.disabled = false;
                    }, 2000);
                } else {
                    alert(result.error || "保存失败，请重试");
                    saveBtn.textContent = originalText;
                    saveBtn.disabled = false;
                }
            } catch (error) {
                alert("网络错误，请检查连接后重试");
                saveBtn.textContent = originalText;
                saveBtn.disabled = false;
            }
        }

        function getCookie(name) {
            const value = \`; \${document.cookie}\`;
            const parts = value.split(\`; \${name}=\`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        }

        // 绑定事件
        document.getElementById("copyBtn").addEventListener("click", copyContent);

        ${canWrite(permission) ? `
        document.getElementById("editBtn").addEventListener("click", enterEditMode);
        document.getElementById("saveBtn").addEventListener("click", saveDocument);
        document.getElementById("cancelBtn").addEventListener("click", cancelEdit);
        ` : ''}

        // 键盘快捷键支持
        document.addEventListener("keydown", function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'c' && !window.getSelection().toString()) {
                e.preventDefault();
                copyContent();
            }

            ${canWrite(permission) ? `
            // Ctrl+S 保存
            if ((e.ctrlKey || e.metaKey) && e.key === 's' && isEditing) {
                e.preventDefault();
                saveDocument();
            }

            // Esc 取消编辑
            if (e.key === 'Escape' && isEditing) {
                e.preventDefault();
                cancelEdit();
            }
            ` : ''}
        });
    </script>
</body>
</html>`;
}

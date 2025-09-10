
/**
 * Cloudflare Workers 网络粘贴板 - 修复版本
 * 使用模板字符串避免复杂的字符串拼接问题
 */

// ==================== 统一配置管理 ====================

// 统一配置对象
const APP_CONFIG = {
  // 安全配置
  SECURITY: {
    // 密码从环境变量读取，不提供默认值以确保安全性
    get ADMIN_PASSWORD() {
      return globalThis.ADMIN_PASSWORD;
    },
    MAX_LOGIN_ATTEMPTS: 5, // 每小时最大尝试次数
    ATTEMPT_WINDOW: 60 * 60 * 1000, // 尝试次数重置窗口1小时
  },

  // 会话配置
  SESSION: {
    ADMIN_DURATION: 24 * 60 * 60 * 1000,    // 管理员会话24小时
    GUEST_DURATION: 60 * 60 * 1000,         // 访客会话1小时
  },

  // 文档配置
  DOCUMENT: {
    DEFAULT_EXPIRY: 7 * 24 * 60 * 60 * 1000, // 默认过期时间7天
  },

  // 权限类型定义
  PERMISSION_TYPES: {
    ADMIN: 'admin',      // 管理员：可操作所有文档
    GUEST: 'guest'       // 访客：只能访问有权限的文档
  },

  // 文档访问级别
  DOC_ACCESS_LEVELS: {
    PUBLIC_READ: 'public_read',       // 公开只读
    PUBLIC_WRITE: 'public_write',     // 公开可编辑
    PASSWORD_READ: 'password_read',   // 密码保护只读
    PASSWORD_WRITE: 'password_write', // 密码保护可编辑
    PRIVATE: 'private'                // 仅管理员可访问
  },

  // 用户权限级别
  PERMISSION_LEVELS: {
    READ: 'read',
    WRITE: 'write',
    ADMIN: 'admin'
  }
};

// 向后兼容的配置别名
const CONFIG = {
  get PASSWORD() { return APP_CONFIG.SECURITY.ADMIN_PASSWORD; },
  get DEFAULT_EXPIRY() { return APP_CONFIG.DOCUMENT.DEFAULT_EXPIRY; },
  get MAX_LOGIN_ATTEMPTS() { return APP_CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS; },
  get ATTEMPT_WINDOW() { return APP_CONFIG.SECURITY.ATTEMPT_WINDOW; }
};

const PERMISSION_TYPES = APP_CONFIG.PERMISSION_TYPES;
const DOC_ACCESS_LEVELS = APP_CONFIG.DOC_ACCESS_LEVELS;
const PERMISSION_LEVELS = APP_CONFIG.PERMISSION_LEVELS;
const SESSION_CONFIG = APP_CONFIG.SESSION;

// ==================== 通用文档操作函数 ====================

// 通用文档获取函数 - 优化重复的KV查询模式
async function getDocumentByName(docName) {
  try {
    // 先通过名称获取文档ID
    const docId = await NOTEPAD_KV.get('name_' + docName);
    if (!docId) {
      return { success: false, error: 'Document not found', code: 404 };
    }

    // 再获取文档数据
    const docData = await NOTEPAD_KV.get('doc_' + docId);
    if (!docData) {
      return { success: false, error: 'Document not found', code: 404 };
    }

    // 解析文档数据
    const document = safeJsonParse(docData);
    if (!document || !document.id) {
      return { success: false, error: 'Document not found', code: 404 };
    }

    return { success: true, document, docId };
  } catch (error) {
    console.error('Error getting document by name:', error);
    return { success: false, error: 'Internal server error', code: 500 };
  }
}

// 检查标题重名（友好提示，不强制）
async function checkTitleDuplication(title, excludeDocId = null) {
  try {
    if (!title || title.trim() === '') {
      return { hasDuplication: false, count: 0 };
    }

    const normalizedTitle = title.trim().toLowerCase();
    let duplicateCount = 0;
    const suggestions = [];

    // 获取所有文档列表（这里简化实现，实际可能需要更高效的索引）
    const { keys } = await NOTEPAD_KV.list({ prefix: 'doc_' });

    // 限制检查数量以避免性能问题
    const maxCheck = Math.min(keys.length, 100);

    for (let i = 0; i < maxCheck; i++) {
      const key = keys[i];
      if (excludeDocId && key.name === 'doc_' + excludeDocId) {
        continue; // 排除当前编辑的文档
      }

      try {
        const docData = await NOTEPAD_KV.get(key.name);
        if (docData) {
          const document = safeJsonParse(docData);
          if (document && document.title) {
            const docTitle = document.title.trim().toLowerCase();
            if (docTitle === normalizedTitle) {
              duplicateCount++;
              if (suggestions.length < 3) {
                // 生成建议标题
                suggestions.push(`${title} (${new Date(document.createdAt).toLocaleDateString()})`);
              }
            }
          }
        }
      } catch (error) {
        // 忽略单个文档的错误，继续检查其他文档
        continue;
      }
    }

    return {
      hasDuplication: duplicateCount > 0,
      count: duplicateCount,
      suggestions: suggestions.slice(0, 2) // 最多返回2个建议
    };
  } catch (error) {
    console.error('Error checking title duplication:', error);
    return { hasDuplication: false, count: 0 };
  }
}

// 通用文档获取函数 - 通过ID获取
async function getDocumentById(docId) {
  try {
    const docData = await NOTEPAD_KV.get('doc_' + docId);
    if (!docData) {
      return { success: false, error: 'Document not found', code: 404 };
    }

    const document = safeJsonParse(docData);
    if (!document || !document.id) {
      return { success: false, error: 'Document not found', code: 404 };
    }

    return { success: true, document };
  } catch (error) {
    console.error('Error getting document by ID:', error);
    return { success: false, error: 'Internal server error', code: 500 };
  }
}

// 更新文档访问统计
async function updateDocumentStats(docId, document) {
  try {
    document.viewCount = (document.viewCount || 0) + 1;
    document.lastViewedAt = Date.now();
    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));
    return true;
  } catch (error) {
    console.error('Error updating document stats:', error);
    return false;
  }
}

// ==================== 阅后即焚功能 ====================

// 检查并处理阅后即焚逻辑
async function checkBurnAfterReading(docId, document, session) {
  try {
    // 如果不是阅后即焚文档，直接返回
    if (!document.burnAfterReading) {
      return { canAccess: true };
    }

    // 如果是管理员，不触发阅后即焚
    if (session && session.type === PERMISSION_TYPES.ADMIN) {
      console.log('管理员访问阅后即焚文档，不触发销毁');
      return { canAccess: true };
    }

    // 检查是否已有锁定记录
    const lockKey = 'burn_lock_' + docId;
    let existingLock;

    try {
      existingLock = await NOTEPAD_KV.get(lockKey);
    } catch (kvError) {
      console.error('KV获取锁定记录失败:', kvError);
      // KV操作失败时，允许访问但不创建锁定
      return { canAccess: true };
    }

    if (existingLock) {
      try {
        const lockData = JSON.parse(existingLock);
        const lockAge = Date.now() - lockData.startTime;

        // 如果锁定超过30秒，清理过期文档
        if (lockAge > 30000) {
          console.log('阅后即焚锁定已过期，删除文档:', docId);
          await deleteBurnDocument(docId, document);
          return { canAccess: false, error: '文档已销毁' };
        }

        // 锁定仍然有效，拒绝访问
        const remainingTime = Math.ceil((30000 - lockAge) / 1000);
        return {
          canAccess: false,
          error: `文档正在被他人访问，请 ${remainingTime} 秒后重试`
        };
      } catch (parseError) {
        console.error('解析锁定数据失败:', parseError);
        // 解析失败时删除损坏的锁定记录
        await NOTEPAD_KV.delete(lockKey);
      }
    }

    // 创建新的锁定记录
    const lockData = {
      startTime: Date.now(),
      docId: docId,
      userId: session?.type || 'anonymous'
    };

    try {
      // 设置60秒TTL，给删除操作留出时间
      await NOTEPAD_KV.put(lockKey, JSON.stringify(lockData), { expirationTtl: 60 });
      console.log('创建阅后即焚锁定:', docId);
    } catch (kvError) {
      console.error('创建锁定记录失败:', kvError);
      // 创建锁定失败时，仍然允许访问
    }

    return { canAccess: true, burnCountdown: true };
  } catch (error) {
    console.error('checkBurnAfterReading函数出错:', error);
    // 出错时允许正常访问
    return { canAccess: true };
  }
}

// 删除阅后即焚文档
async function deleteBurnDocument(docId, document) {
  try {
    // 删除文档数据
    await NOTEPAD_KV.delete('doc_' + docId);

    // 删除名称映射
    if (document.name) {
      await NOTEPAD_KV.delete('name_' + document.name);
    }

    // 删除锁定记录
    await NOTEPAD_KV.delete('burn_lock_' + docId);

    console.log('阅后即焚文档已删除:', docId);
    return true;
  } catch (error) {
    console.error('删除阅后即焚文档失败:', error);
    return false;
  }
}

// 清理过期的阅后即焚文档
async function cleanupExpiredBurnDocs() {
  try {
    const lockList = await NOTEPAD_KV.list({ prefix: 'burn_lock_' });
    const now = Date.now();

    for (const key of lockList.keys) {
      const lockData = await NOTEPAD_KV.get(key.name);
      if (lockData) {
        const lock = JSON.parse(lockData);
        const lockAge = now - lock.startTime;

        // 如果锁定超过30秒，删除对应文档
        if (lockAge > 30000) {
          const docId = lock.docId;
          const docData = await NOTEPAD_KV.get('doc_' + docId);
          if (docData) {
            const document = JSON.parse(docData);
            await deleteBurnDocument(docId, document);
          }
        }
      }
    }
  } catch (error) {
    console.error('清理过期阅后即焚文档失败:', error);
  }
}

// 处理阅后即焚文档删除API
async function handleBurnDocumentDelete(docId, request) {
  try {
    // 获取文档信息
    const docData = await NOTEPAD_KV.get('doc_' + docId);
    if (!docData) {
      return new Response(JSON.stringify({ error: '文档不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const document = safeJsonParse(docData);
    if (!document) {
      return new Response(JSON.stringify({ error: '文档数据损坏' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 检查是否为阅后即焚文档
    if (!document.burnAfterReading) {
      return new Response(JSON.stringify({ error: '非阅后即焚文档' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 检查是否有有效的锁定记录（可选验证）
    const lockKey = 'burn_lock_' + docId;
    const existingLock = await NOTEPAD_KV.get(lockKey);

    // 如果有锁定记录，验证是否过期
    if (existingLock) {
      try {
        const lockData = JSON.parse(existingLock);
        const lockAge = Date.now() - lockData.startTime;

        // 如果锁定超过60秒，认为已过期
        if (lockAge > 60000) {
          console.log('锁定记录已过期，但仍允许删除');
        }
      } catch (parseError) {
        console.error('解析锁定数据失败:', parseError);
      }
    } else {
      console.log('未找到锁定记录，但仍允许删除阅后即焚文档');
    }

    // 删除文档
    const deleteResult = await deleteBurnDocument(docId, document);

    if (deleteResult) {
      return new Response(JSON.stringify({ success: true, message: '文档已销毁' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ error: '删除文档失败' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error('处理阅后即焚删除请求失败:', error);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ==================== 工具函数 ====================

function generateId() {
  // 使用更安全的随机ID生成
  return generateSecureId(24);
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

  // 对于简单的 ID 字符串，只需要转义引号和反斜杠
  // 对于内容字符串，需要转义换行符等
  return text
    .replace(/\\/g, '\\\\')   // 反斜杠必须首先处理
    .replace(/"/g, '\\"')     // 双引号
    .replace(/'/g, "\\'")     // 单引号
    .replace(/\n/g, '\\n')    // 换行符
    .replace(/\r/g, '\\r')    // 回车符
    .replace(/\t/g, '\\t')    // 制表符
    .replace(/\f/g, '\\f')    // 换页符
    .replace(/\v/g, '\\v')    // 垂直制表符
    .replace(/`/g, '\\`');    // 反引号
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

  // 文档编辑路由
  if (path.startsWith('/edit/')) {
    const docId = decodeURIComponent(path.split('/')[2]);
    return handleEditView(docId, request);
  }

  // 直接文档访问路由 - 放在最后以避免与其他路由冲突
  if (path.length > 1 && !path.includes('.')) {
    const docName = decodeURIComponent(path.substring(1)); // 移除开头的 '/'
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
  // 阅后即焚文档删除API
  if (path.startsWith('/api/burn-document/') && method === 'DELETE') {
    const docId = decodeURIComponent(path.split('/')[3]);
    return handleBurnDocumentDelete(docId, request);
  }

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
    const docName = decodeURIComponent(path.split('/')[4]);
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

  // 检查标题重名API
  if (path === '/api/admin/check-title' && method === 'POST') {
    return handleCheckTitle(request);
  }

  // 文档管理API
  if (path === '/api/admin/documents' && method === 'GET') {
    return handleGetDocuments();
  }

  if (path === '/api/admin/documents' && method === 'POST') {
    return handleCreateDocument(request);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'GET') {
    const docId = decodeURIComponent(path.split('/')[4]);
    return handleGetDocument(docId);
  }

  // 文档属性管理API（必须在通用PUT路由之前）
  if (path.startsWith('/api/admin/documents/') && path.endsWith('/properties') && method === 'PUT') {
    const docId = decodeURIComponent(path.split('/')[4]);
    return handleUpdateDocumentProperties(docId, request);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'PUT') {
    const docId = decodeURIComponent(path.split('/')[4]);
    return handleUpdateDocument(docId, request);
  }

  if (path.startsWith('/api/admin/documents/') && method === 'DELETE') {
    const docId = decodeURIComponent(path.split('/')[4]);
    return handleDeleteDocument(docId);
  }

  return new Response(JSON.stringify({ error: 'API not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 公开API处理（根据文档权限验证）
async function handlePublicAPI(request, path, method) {
  if (path.startsWith('/api/public/doc/') && method === 'GET') {
    const docName = decodeURIComponent(path.split('/')[4]);
    return handleGetDocByName(docName, request);
  }

  if (path.startsWith('/api/public/documents/') && method === 'PUT') {
    const docName = decodeURIComponent(path.split('/')[4]);
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

  // 文档直接访问API重定向到新API
  if (path.startsWith('/api/doc/') && method === 'GET') {
    const docName = decodeURIComponent(path.split('/')[3]);
    return handlePublicAPI(request, `/api/public/doc/${encodeURIComponent(docName)}`, method);
  }

  if (path.startsWith('/api/doc/') && path.endsWith('/verify') && method === 'POST') {
    const docName = decodeURIComponent(path.split('/')[3]);
    return handleAuthAPI(request, `/api/auth/verify-doc/${encodeURIComponent(docName)}`, method);
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

    // 检查是否设置了管理员密码
    const adminPassword = CONFIG.PASSWORD;
    if (!adminPassword) {
      console.error('ADMIN_PASSWORD environment variable is not set');
      return new Response(JSON.stringify({
        success: false,
        error: '请检查 `ADMIN_PASSWORD` 环境变量设置'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (password === adminPassword) {
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
          burnAfterReading: doc.burnAfterReading || false,
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

// 检查标题重名
async function handleCheckTitle(request) {
  try {
    const requestData = await request.json();
    const { title, excludeDocId } = requestData;

    if (!title || title.trim() === '') {
      return new Response(JSON.stringify({
        hasDuplication: false,
        count: 0
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const result = await checkTitleDuplication(title, excludeDocId);

    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error checking title:', error);
    return new Response(JSON.stringify({
      hasDuplication: false,
      count: 0
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 创建文档
async function handleCreateDocument(request) {
  try {
    const requestData = await request.json();
    const { title, content, expiryDays, customName, password, accessLevel, burnAfterReading } = requestData;

    // 调试信息
    console.log('Create document request:', {
      title: `"${title}" (length: ${title?.length})`,
      content: `"${content}" (length: ${content?.length})`,
      expiryDays,
      customName: `"${customName}" (length: ${customName?.length})`,
      password: password ? `"${password}" (length: ${password.length})` : undefined,
      accessLevel,
      burnAfterReading
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

    // 验证文档名称（现在是必填的）
    if (!customName || customName.trim() === '') {
      console.log('CustomName is required but not provided');
      return new Response(JSON.stringify({
        error: '文档名称为必填项'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

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
      name: customName, // 现在总是有值，不再是可选的
      title: sanitizeInput(title || 'Untitled', 'title'),
      content: sanitizeInput(content || '', 'content'),
      password: password ? await hashPassword(password) : null,
      accessLevel: finalAccessLevel,
      burnAfterReading: burnAfterReading === true, // 新增：阅后即焚标志
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

    // 创建名称到ID的映射（现在总是需要）
    await NOTEPAD_KV.put('name_' + customName, docId, kvOptions);

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

  // 为管理员API添加hasPassword和burnAfterReading字段
  const responseData = {
    ...document,
    hasPassword: !!document.password,
    burnAfterReading: document.burnAfterReading || false
  };

  return new Response(JSON.stringify(responseData), {
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
    // 只有在提供了title时才验证title
    if (title !== undefined) {
      const titleValidation = validateInput(title, 'title');
      if (!titleValidation.valid) {
        return new Response(JSON.stringify({ error: titleValidation.error || 'Invalid title' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    const contentValidation = validateInput(content, 'content', { allowEmpty: true });
    if (!contentValidation.valid) {
      return new Response(JSON.stringify({ error: contentValidation.error || 'Invalid content' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 使用通用文档获取函数
    const result = await getDocumentByName(docName);
    if (!result.success) {
      return new Response(JSON.stringify({ error: result.error }), {
        status: result.code,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { document, docId } = result;

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
    // 检查是否为管理员权限，只有管理员可以修改标题
    if (title !== undefined && canAdmin(permission)) {
      document.title = sanitizeInput(title, 'title');
    }
    if (content !== undefined) {
      document.content = sanitizeInput(content, 'content');
    }
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

// 更新文档属性（管理员专用）
async function handleUpdateDocumentProperties(docId, request) {
  try {
    console.log('handleUpdateDocumentProperties 被调用，docId:', docId);
    const requestData = await request.json();
    console.log('请求数据:', requestData);
    const { title, content, accessLevel, password, expiryDays, burnAfterReading } = requestData;

    const docData = await NOTEPAD_KV.get('doc_' + docId);
    if (!docData) {
      return new Response(JSON.stringify({ error: 'Document not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const document = JSON.parse(docData);

    // 更新基本信息
    if (title !== undefined) {
      document.title = sanitizeInput(title, 'title');
    }
    if (content !== undefined) {
      document.content = sanitizeInput(content, 'content');
    }

    // 更新访问级别
    if (accessLevel !== undefined) {
      document.accessLevel = accessLevel;
    }

    // 更新密码
    if (password !== undefined) {
      console.log('更新密码 - 原密码:', document.password);
      console.log('更新密码 - 新密码:', password);
      if (password) {
        const newHashedPassword = await hashPassword(password);
        console.log('更新密码 - 新哈希:', newHashedPassword);
        document.password = newHashedPassword;
      } else {
        // 清除密码
        console.log('更新密码 - 清除密码');
        document.password = null;
      }
      console.log('更新密码 - 更新后密码:', document.password);
    }

    // 更新过期时间
    if (expiryDays !== undefined) {
      if (expiryDays === -1) {
        document.expiresAt = null; // 永不过期
      } else {
        const now = Date.now();
        document.expiresAt = now + (expiryDays * 24 * 60 * 60 * 1000);
      }
    }

    // 更新阅后即焚设置
    if (burnAfterReading !== undefined) {
      document.burnAfterReading = burnAfterReading === true;
    }

    document.updatedAt = Date.now();

    await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document));
    console.log('文档已保存到KV，最终密码:', document.password);

    const responseData = {
      success: true,
      document: {
        id: document.id,
        name: document.name,
        title: document.title,
        accessLevel: document.accessLevel,
        hasPassword: !!document.password,
        burnAfterReading: document.burnAfterReading || false,
        expiresAt: document.expiresAt,
        updatedAt: document.updatedAt
      }
    };

    console.log('返回响应数据:', responseData);
    return new Response(JSON.stringify(responseData), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Error updating document properties:', error);
    return new Response(JSON.stringify({ error: 'Failed to update document properties' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 通过名称获取文档（用于直接访问）
async function handleGetDocByName(docName, request) {
  // 使用通用文档获取函数
  const result = await getDocumentByName(docName);
  if (!result.success) {
    return new Response(JSON.stringify({ error: result.error }), {
      status: result.code,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { document, docId } = result;

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

  // 如果有读取权限，检查阅后即焚逻辑
  if (canRead(permission)) {
    // 检查阅后即焚逻辑
    const burnCheck = await checkBurnAfterReading(docId, document, session);
    if (!burnCheck.canAccess) {
      return new Response(JSON.stringify({ error: burnCheck.error }), {
        status: burnCheck.error === '文档已销毁' ? 404 : 423,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    response.content = document.content || '';
    response.burnCountdown = burnCheck.burnCountdown || false;

    // 使用通用函数更新访问统计
    await updateDocumentStats(docId, document);
  }

  return new Response(JSON.stringify(response), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 验证文档密码
async function handleVerifyDocPassword(docName, request) {
  const { password } = await request.json();
  const ip = getClientIP(request);

  // 使用通用文档获取函数
  const result = await getDocumentByName(docName);
  if (!result.success) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { document, docId } = result;

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

  // 使用通用函数更新访问统计
  await updateDocumentStats(docId, document);

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
  // 使用通用文档获取函数
  const result = await getDocumentByName(docName);
  if (!result.success) {
    return new Response(get404HTML(), {
      status: 404,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  const { document, docId } = result;

  // 使用统一的会话验证系统
  const session = await validateSession(request);
  const permission = await getDocumentPermission(session, document);

  // 如果有读取权限，检查阅后即焚逻辑
  if (canRead(permission)) {
    // 检查阅后即焚逻辑（已添加错误处理）
    const burnCheck = await checkBurnAfterReading(docId, document, session);
    if (!burnCheck.canAccess) {
      if (burnCheck.error === '文档已销毁') {
        return new Response(get404HTML(), {
          status: 404,
          headers: { 'Content-Type': 'text/html' }
        });
      } else {
        // 显示访问冲突页面
        return new Response(getBurnConflictHTML(burnCheck.error), {
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }

    // 使用通用函数更新访问统计
    await updateDocumentStats(docId, document);

    // 如果是阅后即焚文档，显示倒计时页面
    if (burnCheck.burnCountdown) {
      return new Response(getBurnCountdownHTML(document, permission), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

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

// 编辑页面视图
async function handleEditView(docId, request) {
  // 使用统一的会话验证系统
  const session = await validateSession(request);

  if (!session) {
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

// ==================== 公共前端工具函数库 ====================

// 生成公共JavaScript工具函数
function getCommonJavaScript() {
  return `
    // 公共工具函数库
    window.CFNotepadUtils = {
      // Cookie操作
      getCookie: function(name) {
        const value = "; " + document.cookie;
        const parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop().split(";").shift();
        return null;
      },

      setCookie: function(name, value, days = 7) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = name + "=" + value + ";expires=" + expires.toUTCString() + ";path=/";
      },

      // 会话管理
      getSessionToken: function() {
        return localStorage.getItem("sessionToken") || this.getCookie("sessionToken");
      },

      setSessionToken: function(token) {
        localStorage.setItem("sessionToken", token);
        this.setCookie("sessionToken", token);
      },

      clearSession: function() {
        localStorage.removeItem("sessionToken");
        document.cookie = "sessionToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
      },

      // API调用
      apiCall: async function(endpoint, options = {}) {
        const sessionToken = this.getSessionToken();
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
          this.clearSession();
          window.location.reload();
          return;
        }

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
          throw new Error(errorData.error || "HTTP " + response.status + ": " + response.statusText);
        }

        return response;
      },

      // 错误处理
      showError: function(message) {
        alert("错误: " + message);
      },

      showSuccess: function(message) {
        alert("成功: " + message);
      },

      // HTML转义
      escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
      },

      // JavaScript字符串转义
      escapeJavaScript: function(text) {
        if (typeof text !== 'string') return '';
        return text
          .replace(/\\\\/g, '\\\\\\\\')
          .replace(/'/g, "\\\\'")
          .replace(/"/g, '\\\\"')
          .replace(/\\n/g, '\\\\n')
          .replace(/\\r/g, '\\\\r')
          .replace(/\\t/g, '\\\\t');
      }
    };
  `;
}

// ==================== HTML 页面生成函数 ====================

// 现代化样式系统
function getModernStyles() {
  return `
    <style>
      :root {
        --primary-50: #eff6ff;
        --primary-100: #dbeafe;
        --primary-500: #3b82f6;
        --primary-600: #2563eb;
        --primary-700: #1d4ed8;
        --success-500: #10b981;
        --success-600: #059669;
        --warning-500: #f59e0b;
        --warning-600: #d97706;
        --danger-500: #ef4444;
        --danger-600: #dc2626;
        --gray-50: #f9fafb;
        --gray-100: #f3f4f6;
        --gray-900: #111827;
      }

      /* 触控友好的按钮基础样式 */
      .btn-base {
        min-height: 44px;
        padding: 12px 24px;
        border-radius: 12px;
        font-weight: 600;
        transition: all 0.2s ease;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        display: inline-flex;
        align-items: center;
        justify-content: center;
        text-decoration: none;
        border: none;
        cursor: pointer;
        font-size: 14px;
        line-height: 1.25;
      }

      .btn-base:active {
        transform: scale(0.95);
      }

      .btn-base:focus {
        outline: none;
        ring: 4px;
        ring-opacity: 50%;
      }

      /* 主要按钮样式 */
      .btn-primary {
        background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
        color: white;
      }

      .btn-primary:hover {
        background: linear-gradient(135deg, var(--primary-600), var(--primary-700));
        box-shadow: 0 8px 15px -3px rgba(59, 130, 246, 0.3);
      }

      .btn-primary:focus {
        ring-color: var(--primary-200);
      }

      /* 成功按钮样式 */
      .btn-success {
        background: linear-gradient(135deg, var(--success-500), var(--success-600));
        color: white;
      }

      .btn-success:hover {
        background: linear-gradient(135deg, var(--success-600), #047857);
        box-shadow: 0 8px 15px -3px rgba(16, 185, 129, 0.3);
      }

      /* 危险按钮样式 */
      .btn-danger {
        background: linear-gradient(135deg, var(--danger-500), var(--danger-600));
        color: white;
      }

      .btn-danger:hover {
        background: linear-gradient(135deg, var(--danger-600), #b91c1c);
        box-shadow: 0 8px 15px -3px rgba(239, 68, 68, 0.3);
      }

      /* 次要按钮样式 */
      .btn-secondary {
        background: linear-gradient(135deg, #6b7280, #4b5563);
        color: white;
      }

      .btn-secondary:hover {
        background: linear-gradient(135deg, #4b5563, #374151);
        box-shadow: 0 8px 15px -3px rgba(107, 114, 128, 0.3);
      }

      /* 小按钮样式 */
      .btn-sm {
        min-height: 36px;
        padding: 8px 16px;
        font-size: 13px;
      }

      /* 图标按钮样式 */
      .btn-icon {
        min-height: 44px;
        min-width: 44px;
        padding: 10px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background: transparent;
        border: none;
        border-radius: 8px;
        color: #6b7280; /* text-gray-500 */
        transition: all 0.2s ease;
        cursor: pointer;
        text-decoration: none;
      }

      .btn-icon:hover {
        background-color: #f3f4f6; /* bg-gray-100 */
        color: #374151; /* text-gray-700 */
        transform: none;
        box-shadow: none;
      }

      .btn-icon:active {
        transform: scale(0.95);
        background-color: #e5e7eb; /* bg-gray-200 */
      }

      .btn-icon:focus {
        outline: none;
        ring: 2px;
        ring-color: #d1d5db; /* ring-gray-300 */
        ring-opacity: 50%;
      }

      .btn-icon svg {
        width: 24px;
        height: 24px;
      }

      /* 特殊颜色的图标按钮 */
      .btn-icon.btn-icon-danger {
        color: #dc2626; /* text-red-600 */
      }

      .btn-icon.btn-icon-danger:hover {
        color: #b91c1c; /* text-red-700 */
        background-color: #fef2f2; /* bg-red-50 */
      }

      .btn-icon.btn-icon-success {
        color: #059669; /* text-emerald-600 */
      }

      .btn-icon.btn-icon-success:hover {
        color: #047857; /* text-emerald-700 */
        background-color: #ecfdf5; /* bg-emerald-50 */
      }

      .btn-icon.btn-icon-primary {
        color: #2563eb; /* text-blue-600 */
      }

      .btn-icon.btn-icon-primary:hover {
        color: #1d4ed8; /* text-blue-700 */
        background-color: #eff6ff; /* bg-blue-50 */
      }

      /* 现代化输入框样式 */
      .input-modern {
        min-height: 44px;
        padding: 12px 16px;
        border: 2px solid #e5e7eb;
        border-radius: 12px;
        transition: all 0.2s ease;
        font-size: 16px; /* 防止iOS缩放 */
      }

      .input-modern:focus {
        outline: none;
        border-color: var(--primary-500);
        ring: 4px;
        ring-color: var(--primary-100);
        ring-opacity: 50%;
      }

      /* 现代化卡片样式 */
      .card-modern {
        background: white;
        border-radius: 16px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        border: 1px solid rgba(0, 0, 0, 0.05);
      }

      /* 渐变背景 */
      .bg-gradient-modern {
        background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
      }

      /* 移动端优化 */
      @media (max-width: 640px) {
        .btn-base {
          width: 100%;
          margin-bottom: 8px;
        }

        .btn-group-mobile {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .btn-group-mobile .btn-base {
          margin-bottom: 0;
        }

        .card-modern {
          margin: 4px;
          border-radius: 8px;
        }

        .input-modern {
          font-size: 16px; /* 防止iOS Safari缩放 */
        }

        /* 移动端紧凑布局 */
        .mobile-compact-container {
          padding: 8px !important;
        }

        .mobile-compact-card {
          padding: 12px !important;
          margin-bottom: 8px !important;
        }

        .mobile-compact-main {
          padding-top: 12px !important;
          padding-bottom: 12px !important;
        }

        .mobile-compact-header {
          padding-top: 16px !important;
          padding-bottom: 16px !important;
        }

        /* 文本区域优化 */
        .mobile-text-area {
          min-height: 60vh !important;
        }

        .mobile-content-display {
          padding: 12px !important;
          min-height: 65vh !important;
        }
      }

      /* 平板端优化 */
      @media (min-width: 641px) and (max-width: 1024px) {
        .btn-group-tablet {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
        }
      }

      /* 桌面端优化 */
      @media (min-width: 1025px) {
        .btn-group-desktop {
          display: flex;
          gap: 12px;
        }

        .btn-group-desktop .btn-base {
          width: auto;
        }
      }
    </style>
  `;
}

function getMainHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen">
    <!-- 登录模态框 -->
    <div id="loginModal" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
        <div class="card-modern p-8 max-w-md w-full">
            <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">登录验证</h2>
            <form id="loginForm">
                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">密码</label>
                    <input type="password" id="passwordInput" class="input-modern w-full" placeholder="请输入密码" required>
                </div>
                <button type="submit" class="btn-base btn-primary w-full">
                    登录
                </button>
            </form>
            <div id="loginError" class="mt-4 text-red-500 text-sm hidden"></div>
        </div>
    </div>

    <!-- 主界面 -->
    <div id="mainApp" class="hidden">
        <header class="bg-white shadow-lg border-b border-gray-100">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center py-6 gap-4">
                    <h1 class="text-3xl font-bold text-gray-900 text-center sm:text-left">CF Notepad</h1>
                    <div class="flex">
                        <button id="logoutBtn" class="btn-icon btn-icon-danger" title="退出登录">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8 mobile-compact-main">
            <div class="px-4 py-6 sm:px-0 mobile-compact-container">
                <!-- 创建新文档按钮 -->
                <div class="mb-8">
                    <button id="createDocBtn" class="btn-base btn-success">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                        </svg>
                        创建新文档
                    </button>
                </div>

                <!-- 文档列表 -->
                <div class="card-modern">
                    <div class="px-6 py-6 sm:p-8 mobile-compact-card">
                        <h3 class="text-xl font-semibold text-gray-900 mb-6">文档列表</h3>
                        <div id="documentsList" class="space-y-4">
                            <!-- 文档列表将在这里动态加载 -->
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- 创建文档模态框 -->
    <div id="createModal" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 hidden p-4">
        <div class="card-modern p-8 max-w-lg w-full max-h-screen overflow-y-auto">
            <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">创建新文档</h2>
            <form id="createForm">
                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">文档标题</label>
                    <input type="text" id="titleInput" class="input-modern w-full" placeholder="请输入文档标题" required>
                    <div id="titleWarning" class="hidden mt-2 p-2 bg-yellow-50 border border-yellow-200 rounded text-sm text-yellow-800">
                        <div class="flex items-center">
                            <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                            </svg>
                            <span id="titleWarningText"></span>
                        </div>
                    </div>
                </div>

                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">
                        文档名称 <span class="text-red-500">*</span>
                        <span class="text-gray-500 font-normal">(用于直接访问)</span>
                    </label>
                    <input type="text" id="customNameInput"
                           class="input-modern w-full"
                           placeholder="例如: my-document (3-50个字符，仅限字母数字-_)"
                           required>
                    <div class="text-xs text-gray-500 mt-2">
                        通过 域名/文档名称 直接访问，名称必须唯一
                    </div>
                </div>

                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">访问权限</label>
                    <select id="accessLevelSelect" class="input-modern w-full">
                        <option value="public_read">公开只读 - 任何人都可以查看，但不能编辑</option>
                        <option value="public_write">公开可编辑 - 任何人都可以查看和编辑</option>
                        <option value="password_read">密码保护只读 - 需要密码才能查看</option>
                        <option value="password_write">密码保护可编辑 - 需要密码才能查看和编辑</option>
                        <option value="private">私有 - 仅管理员可访问</option>
                    </select>
                    <div class="text-xs text-gray-500 mt-2">
                        选择文档的访问权限级别
                    </div>
                </div>

                <div class="mb-6" id="passwordSection" style="display: none;">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">
                        访问密码
                        <span class="text-red-500">*</span>
                    </label>
                    <input type="password" id="createPasswordInput"
                           class="input-modern w-full"
                           placeholder="设置密码保护文档">
                    <div class="text-xs text-gray-500 mt-2">
                        密码保护文档需要设置访问密码
                    </div>
                </div>

                <div class="mb-6">
                    <label class="block text-gray-700 text-sm font-semibold mb-3">过期时间</label>
                    <select id="expirySelect" class="input-modern w-full">
                        <option value="1">1天</option>
                        <option value="7" selected>7天</option>
                        <option value="30">30天</option>
                        <option value="-1">永久</option>
                    </select>
                </div>

                <div class="mb-8">
                    <div class="flex items-center space-x-3">
                        <input type="checkbox" id="createBurnAfterReadingCheckbox" class="w-4 h-4 text-red-600 bg-gray-100 border-gray-300 rounded focus:ring-red-500 focus:ring-2">
                        <label for="createBurnAfterReadingCheckbox" class="text-gray-700 text-sm font-semibold">
                            🔥 阅后即焚
                        </label>
                    </div>
                    <div class="text-xs text-gray-500 mt-1">
                        启用后，文档被访问30秒后将自动销毁（管理员访问不触发销毁）
                    </div>
                </div>

                <div id="createError" class="mb-6 text-red-500 text-sm hidden"></div>

                <div class="btn-group-mobile sm:btn-group-desktop">
                    <button type="submit" class="btn-base btn-primary flex-1">
                        创建
                    </button>
                    <button type="button" id="cancelCreateBtn" class="btn-base btn-secondary flex-1">
                        取消
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>${getCommonJavaScript()}</script>
    ${getMainScript()}
</body>
</html>`;
}

function getMainScript() {
  return `<script>
    // 使用公共工具函数库
    const utils = window.CFNotepadUtils;
    let sessionToken = utils.getSessionToken();

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

    // 使用公共工具函数的API调用
    async function apiCall(endpoint, options = {}) {
        try {
            return await utils.apiCall(endpoint, options);
        } catch (error) {
            // 如果是会话过期，重新获取token并检查会话
            if (error.message.includes("Session expired") || error.message.includes("401")) {
                sessionToken = utils.getSessionToken();
                checkSession();
            }
            throw error;
        }
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

            // 使用公共工具函数的HTML转义
            const escapeHtml = utils.escapeHtml;

            // 使用公共工具函数的JavaScript转义
            const escapeJavaScript = utils.escapeJavaScript;

            listElement.innerHTML = documents.map(doc => {
                const createdDate = new Date(doc.createdAt).toLocaleString();
                const updatedDate = new Date(doc.updatedAt).toLocaleString();
                const expiryText = doc.expiresAt ? new Date(doc.expiresAt).toLocaleString() : "永久";
                const currentDomain = window.location.origin;

                let directAccessSection = '';
                if (doc.name) {
                    const passwordBadge = doc.hasPassword ? '<span class="ml-2 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 border border-yellow-200">🔒 密码保护</span>' : '';
                    const burnBadge = doc.burnAfterReading ? '<span class="ml-2 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">🔥 阅后即焚</span>' : '';
                    directAccessSection = \`
                        <div class="mb-3">
                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 border border-blue-200">
                                直接访问: \${escapeHtml(doc.name)}
                            </span>
                            \${passwordBadge}
                            \${burnBadge}
                        </div>
                        <div class="mb-3">
                            <a href="/\${encodeURIComponent(doc.name)}" target="_blank" class="text-blue-600 hover:text-blue-800 text-sm underline font-medium">
                                \${currentDomain}/\${escapeHtml(doc.name)}
                            </a>
                            <button onclick="copyDirectLink('\${escapeJavaScript(doc.name)}')" class="ml-3 text-gray-500 hover:text-gray-700 text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded transition-colors">
                                📋 复制链接
                            </button>
                        </div>
                    \`;
                }

                return \`
                    <div class="card-modern p-6 hover:shadow-xl transition-all duration-200 mobile-compact-card">
                        <div class="flex flex-col lg:flex-row lg:justify-between lg:items-start gap-4">
                            <div class="flex-1">
                                <h4 class="text-xl font-semibold text-gray-900 mb-3">\${escapeHtml(doc.title)}</h4>
                                \${directAccessSection}
                                <div class="text-sm text-gray-600 space-y-2">
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                        <p><span class="font-medium">创建时间:</span> \${createdDate}</p>
                                        <p><span class="font-medium">更新时间:</span> \${updatedDate}</p>
                                        <p><span class="font-medium">查看次数:</span> \${doc.viewCount}</p>
                                        <p><span class="font-medium">过期时间:</span> \${expiryText}</p>
                                    </div>
                                </div>
                            </div>
                            <div class="flex gap-1 lg:ml-6">
                                <button onclick="editDocument('\${escapeJavaScript(doc.id)}')" class="btn-icon btn-icon-primary" title="编辑文档">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                                    </svg>
                                </button>
                                <button onclick="shareDocument('\${escapeJavaScript(doc.name || doc.id)}')" class="btn-icon btn-icon-success" title="分享文档">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z"></path>
                                    </svg>
                                </button>
                                <button onclick="deleteDocument('\${escapeJavaScript(doc.id)}')" class="btn-icon btn-icon-danger" title="删除文档">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                    </svg>
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

    function shareDocument(docNameOrId) {
        // 直接复用现有的 copyDirectLink 逻辑
        copyDirectLink(docNameOrId);
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
                utils.setSessionToken(sessionToken);
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

        // 在模态框显示后绑定标题重名检查功能
        const titleInput = document.getElementById("titleInput");
        const warningDiv = document.getElementById("titleWarning");

        if (titleInput && warningDiv) {
            // 移除之前可能存在的监听器
            titleInput.removeEventListener("input", titleInputHandler);

            // 添加新的监听器
            titleInput.addEventListener("input", titleInputHandler);
        }
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

    // 标题重名检查功能
    let titleCheckTimeout;

    // 标题输入处理函数
    function titleInputHandler() {
        const title = this.value.trim();
        const warningDiv = document.getElementById("titleWarning");

        // 清除之前的定时器
        if (titleCheckTimeout) {
            clearTimeout(titleCheckTimeout);
        }

        // 如果标题为空，隐藏警告
        if (!title) {
            warningDiv.classList.add("hidden");
            return;
        }

        // 延迟检查，避免频繁请求
        titleCheckTimeout = setTimeout(async () => {
            try {
                const response = await apiCall("/api/admin/check-title", {
                    method: "POST",
                    body: JSON.stringify({ title: title })
                });

                const data = await response.json();

                if (data.hasDuplication) {
                    const warningText = document.getElementById("titleWarningText");
                    if (data.count === 1) {
                        warningText.textContent = "已有1个文档使用此标题，建议使用更具体的标题";
                    } else {
                        warningText.textContent = "已有" + data.count + "个文档使用此标题，建议使用更具体的标题";
                    }
                    warningDiv.classList.remove("hidden");
                } else {
                    warningDiv.classList.add("hidden");
                }
            } catch (error) {
                // 检查失败时静默处理，不影响用户操作
                console.log("Title check failed:", error);
                warningDiv.classList.add("hidden");
            }
        }, 500); // 500ms延迟
    }

    document.getElementById("createForm").addEventListener("submit", async function(e) {
        e.preventDefault();
        const title = document.getElementById("titleInput").value;
        const customName = document.getElementById("customNameInput").value.trim();
        const password = document.getElementById("createPasswordInput").value;
        const accessLevel = document.getElementById("accessLevelSelect").value;
        const expiryDays = parseInt(document.getElementById("expirySelect").value);
        const burnAfterReading = document.getElementById("createBurnAfterReadingCheckbox").checked;
        const errorDiv = document.getElementById("createError");

        // 隐藏之前的错误信息
        errorDiv.classList.add("hidden");

        // 验证文档名称（必填）
        if (!customName || customName.trim() === '') {
            errorDiv.textContent = "文档名称为必填项";
            errorDiv.classList.remove("hidden");
            return;
        }

        if (!/^[a-zA-Z0-9_-]{3,50}$/.test(customName)) {
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
                accessLevel: accessLevel,
                burnAfterReading: burnAfterReading
            };

            // 文档名称现在是必填的
            requestData.customName = customName;

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
            document.getElementById("createBurnAfterReadingCheckbox").checked = false;

            window.location.href = "/edit/" + newDoc.id;
        } catch (error) {
            const errorMessage = error.message;
            if (errorMessage.includes("文档名称已存在")) {
                // 提供建议的替代名称
                const suggestedName = customName + "-2";
                errorDiv.innerHTML = "文档名称已存在，建议使用: <strong>" + suggestedName + "</strong>";
                errorDiv.classList.remove("hidden");
                // 自动填入建议名称
                document.getElementById("customNameInput").value = suggestedName;
            } else if (errorMessage.includes("文档名称只能包含")) {
                errorDiv.textContent = "文档名称格式不正确";
                errorDiv.classList.remove("hidden");
            } else if (errorMessage.includes("文档名称为必填项")) {
                errorDiv.textContent = "请输入文档名称";
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>编辑文档 - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen">
    <header class="bg-white shadow-lg border-b border-gray-100">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center py-6 gap-4">
                <h1 class="text-3xl font-bold text-gray-900 text-center sm:text-left">编辑文档</h1>
                <div class="flex gap-1">
                    <button id="saveBtn" class="btn-icon btn-icon-success" title="保存文档">
                        <svg fill="currentColor" viewBox="0 0 24 24">
                            <path d="m20.71 9.29l-6-6a1 1 0 0 0-.32-.21A1.1 1.1 0 0 0 14 3H6a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3v-8a1 1 0 0 0-.29-.71M9 5h4v2H9Zm6 14H9v-3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1Zm4-1a1 1 0 0 1-1 1h-1v-3a3 3 0 0 0-3-3h-4a3 3 0 0 0-3 3v3H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h1v3a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V6.41l4 4Z"/>
                        </svg>
                    </button>
                    <button id="shareBtn" class="btn-icon btn-icon-success" title="分享文档">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z"></path>
                        </svg>
                    </button>
                    <a href="/" class="btn-icon btn-icon-danger" title="返回首页">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                        </svg>
                    </a>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8 mobile-compact-main">
        <div class="px-4 py-6 sm:px-0 mobile-compact-container">
            <div class="card-modern">
                <div class="px-6 py-6 sm:p-8 mobile-compact-card">
                    <div class="mb-6">
                        <label class="block text-gray-700 text-sm font-semibold mb-3">文档标题</label>
                        <input type="text" id="titleInput" class="input-modern w-full" placeholder="请输入文档标题">
                        <div id="titleWarning" class="hidden mt-2 p-2 bg-yellow-50 border border-yellow-200 rounded text-sm text-yellow-800">
                            <div class="flex items-center">
                                <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                                </svg>
                                <span id="titleWarningText"></span>
                            </div>
                        </div>
                    </div>

                    <!-- 文档属性管理区域 -->
                    <div class="mb-6 p-4 bg-gray-50 rounded-lg border border-gray-200">
                        <h3 class="text-lg font-semibold text-gray-800 mb-4">文档属性设置</h3>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <!-- 访问权限设置 -->
                            <div>
                                <label class="block text-gray-700 text-sm font-semibold mb-2">访问权限</label>
                                <select id="accessLevelSelect" class="input-modern w-full">
                                    <option value="public_read">公开只读</option>
                                    <option value="public_write">公开可编辑</option>
                                    <option value="password_read">密码保护只读</option>
                                    <option value="password_write">密码保护可编辑</option>
                                    <option value="private">仅管理员可访问</option>
                                </select>
                            </div>

                            <!-- 过期时间设置 -->
                            <div>
                                <label class="block text-gray-700 text-sm font-semibold mb-2">过期时间</label>
                                <select id="expirySelect" class="input-modern w-full">
                                    <option value="1">1天后过期</option>
                                    <option value="7">7天后过期</option>
                                    <option value="30">30天后过期</option>
                                    <option value="-1">永不过期</option>
                                </select>
                            </div>
                        </div>

                        <!-- 密码设置 -->
                        <div class="mt-4">
                            <label class="block text-gray-700 text-sm font-semibold mb-2">访问密码</label>
                            <div class="flex gap-2">
                                <input type="password" id="documentPasswordInput" class="input-modern flex-1 bg-gray-100 text-gray-500" placeholder="设置文档访问密码（可选）" readonly disabled>
                                <button type="button" id="editPasswordBtn" class="btn-icon" title="修改密码">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                                    </svg>
                                </button>
                                <button type="button" id="applyPasswordBtn" class="btn-icon btn-icon-success" title="应用密码修改" style="display: none;">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                    </svg>
                                </button>
                                <button type="button" id="cancelPasswordBtn" class="btn-icon" title="取消密码修改" style="display: none;">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                </button>
                            </div>
                            <div class="text-xs text-gray-500 mt-1">
                                仅在选择密码保护权限时需要设置
                            </div>
                        </div>

                        <!-- 阅后即焚设置 -->
                        <div class="mt-4">
                            <div class="flex items-center space-x-3">
                                <input type="checkbox" id="burnAfterReadingCheckbox" class="w-4 h-4 text-red-600 bg-gray-100 border-gray-300 rounded focus:ring-red-500 focus:ring-2">
                                <label for="burnAfterReadingCheckbox" class="text-gray-700 text-sm font-semibold">
                                    🔥 阅后即焚
                                </label>
                            </div>
                            <div class="text-xs text-gray-500 mt-1">
                                启用后，文档被访问30秒后将自动销毁（管理员访问不触发销毁）
                            </div>
                        </div>
                    </div>

                    <div class="mb-6">
                        <label class="block text-gray-700 text-sm font-semibold mb-3">文档内容</label>
                        <textarea id="contentInput" rows="20" class="input-modern w-full font-mono text-sm leading-relaxed resize-y mobile-text-area" placeholder="请输入文档内容..."></textarea>
                    </div>
                    <div id="statusMessage" class="mt-4 text-sm hidden"></div>
                </div>
            </div>
        </div>
    </main>

    <script>${getCommonJavaScript()}</script>
    <script>
        const docId = "${escapeJavaScript(docId)}";
        const utils = window.CFNotepadUtils;
        let sessionToken = utils.getSessionToken();

        // 密码编辑状态管理
        let isPasswordEditing = false;
        let hasPassword = false;
        let originalPasswordValue = "";
        let pendingPassword = null; // 保存待应用的密码值

        // 使用公共工具函数的API调用
        async function apiCall(endpoint, options = {}) {
            try {
                return await utils.apiCall(endpoint, options);
            } catch (error) {
                if (error.message.includes("Session expired") || error.message.includes("401")) {
                    window.location.href = "/";
                    return;
                }
                throw error;
            }
        }

        let documentName = null; // 存储文档名称用于分享

        async function loadDocument() {
            try {
                const response = await apiCall(\`/api/admin/documents/\${docId}\`);
                const docData = await response.json();

                document.getElementById("titleInput").value = docData.title;
                document.getElementById("contentInput").value = docData.content;

                // 加载文档属性
                document.getElementById("accessLevelSelect").value = docData.accessLevel || "public_read";

                // 处理密码状态显示
                hasPassword = docData.hasPassword || false;
                const passwordInput = document.getElementById("documentPasswordInput");

                // 确保输入框处于正确的disabled状态
                passwordInput.readOnly = true;
                passwordInput.disabled = true;
                passwordInput.className = "input-modern flex-1 bg-gray-100 text-gray-500";

                if (hasPassword) {
                    passwordInput.placeholder = "••••••••（已设置密码）";
                    originalPasswordValue = "••••••••";
                } else {
                    passwordInput.placeholder = "设置文档访问密码（可选）";
                    originalPasswordValue = "";
                }
                passwordInput.value = originalPasswordValue;

                // 设置过期时间
                if (docData.expiresAt) {
                    const daysUntilExpiry = Math.ceil((docData.expiresAt - Date.now()) / (24 * 60 * 60 * 1000));
                    if (daysUntilExpiry <= 1) {
                        document.getElementById("expirySelect").value = "1";
                    } else if (daysUntilExpiry <= 7) {
                        document.getElementById("expirySelect").value = "7";
                    } else if (daysUntilExpiry <= 30) {
                        document.getElementById("expirySelect").value = "30";
                    } else {
                        document.getElementById("expirySelect").value = "-1";
                    }
                } else {
                    document.getElementById("expirySelect").value = "-1";
                }

                // 设置阅后即焚状态
                document.getElementById("burnAfterReadingCheckbox").checked = docData.burnAfterReading || false;

                // 保存文档名称用于分享功能
                documentName = docData.name;
            } catch (error) {
                console.error("Failed to load document:", error);
                showMessage("加载文档失败", "error");
            }
        }

        // 密码编辑模式管理
        function enterPasswordEditMode() {
            isPasswordEditing = true;
            const passwordInput = document.getElementById("documentPasswordInput");
            const editBtn = document.getElementById("editPasswordBtn");
            const applyBtn = document.getElementById("applyPasswordBtn");
            const cancelBtn = document.getElementById("cancelPasswordBtn");

            // 切换按钮显示
            editBtn.style.display = "none";
            applyBtn.style.display = "inline-block";
            cancelBtn.style.display = "inline-block";

            // 启用输入框并清空内容
            passwordInput.readOnly = false;
            passwordInput.disabled = false;
            passwordInput.className = "input-modern flex-1"; // 移除灰色样式
            passwordInput.value = "";
            passwordInput.placeholder = "输入新密码或留空清除密码";
            passwordInput.focus();
        }

        function exitPasswordEditMode() {
            isPasswordEditing = false;
            const passwordInput = document.getElementById("documentPasswordInput");
            const editBtn = document.getElementById("editPasswordBtn");
            const applyBtn = document.getElementById("applyPasswordBtn");
            const cancelBtn = document.getElementById("cancelPasswordBtn");

            // 切换按钮显示
            editBtn.style.display = "inline-block";
            applyBtn.style.display = "none";
            cancelBtn.style.display = "none";

            // 禁用输入框并恢复原始状态
            passwordInput.readOnly = true;
            passwordInput.disabled = true;
            passwordInput.className = "input-modern flex-1 bg-gray-100 text-gray-500"; // 恢复灰色样式
            passwordInput.value = originalPasswordValue;
            if (hasPassword) {
                passwordInput.placeholder = "••••••••（已设置密码）";
            } else {
                passwordInput.placeholder = "设置文档访问密码（可选）";
            }
        }

        function cancelPasswordEdit() {
            // 取消密码编辑，清空待应用的密码
            pendingPassword = null;
            exitPasswordEditMode();
            showMessage("已取消密码修改", "info");
        }

        function applyPasswordChange() {
            const passwordInput = document.getElementById("documentPasswordInput");
            const newPassword = passwordInput.value;

            console.log("应用密码修改:", newPassword ? "设置新密码" : "清除密码");

            // 保存待应用的密码值
            pendingPassword = newPassword;

            // 更新状态
            if (newPassword) {
                hasPassword = true;
                originalPasswordValue = "••••••••";
            } else {
                hasPassword = false;
                originalPasswordValue = "";
            }

            // 退出编辑模式并显示应用成功的消息
            exitPasswordEditMode();
            showMessage("密码已应用，点击保存按钮完成修改", "success");
        }

        function confirmPasswordChange() {
            // 这个函数在保存成功后调用，用于最终确认密码修改
            pendingPassword = null; // 清空待应用的密码
            isPasswordEditing = false; // 确保退出编辑状态
        }

        async function saveDocument() {
            const title = document.getElementById("titleInput").value;
            const content = document.getElementById("contentInput").value;
            const accessLevel = document.getElementById("accessLevelSelect").value;
            const password = document.getElementById("documentPasswordInput").value;
            const expiryDays = parseInt(document.getElementById("expirySelect").value);
            const burnAfterReading = document.getElementById("burnAfterReadingCheckbox").checked;

            // 构建请求数据
            const requestData = {
                title,
                content,
                accessLevel,
                expiryDays,
                burnAfterReading
            };

            // 只在密码被编辑时包含password字段
            if (pendingPassword !== null) {
                console.log("保存文档时包含密码修改:", pendingPassword ? "新密码" : "清除密码");
                requestData.password = pendingPassword;

                // 验证密码保护文档必须设置密码
                if ((accessLevel === "password_read" || accessLevel === "password_write") && !pendingPassword) {
                    showMessage("密码保护文档必须设置访问密码", "error");
                    return;
                }
            } else {
                // 验证密码保护文档必须有密码（无论是现有的还是新设置的）
                if ((accessLevel === "password_read" || accessLevel === "password_write") && !hasPassword) {
                    showMessage("密码保护文档必须设置访问密码", "error");
                    return;
                }
            }

            try {

                const response = await apiCall(\`/api/admin/documents/\${docId}/properties\`, {
                    method: "PUT",
                    body: JSON.stringify(requestData)
                });

                if (response.ok) {
                    showMessage("保存成功", "success");

                    // 如果密码被修改，确认密码修改
                    if (pendingPassword !== null) {
                        confirmPasswordChange();
                    }
                } else {
                    const errorData = await response.json();
                    showMessage("保存失败: " + (errorData.error || "未知错误"), "error");
                }
            } catch (error) {
                console.error("Failed to save document:", error);
                showMessage("保存失败", "error");
            }
        }

        function shareDocument() {
            // 所有文档现在都有名称，可以直接分享
            const url = window.location.origin + "/" + documentName;

            if (navigator.clipboard) {
                navigator.clipboard.writeText(url).then(function() {
                    showMessage("分享链接已复制到剪贴板", "success");
                }).catch(function() {
                    showMessage("复制失败，请手动复制: " + url, "error");
                });
            } else {
                // 降级方案
                const textArea = document.createElement("textarea");
                textArea.value = url;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand("copy");
                    showMessage("分享链接已复制到剪贴板", "success");
                } catch (err) {
                    showMessage("复制失败，请手动复制: " + url, "error");
                }
                document.body.removeChild(textArea);
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

        // 密码编辑按钮
        document.getElementById("editPasswordBtn").addEventListener("click", enterPasswordEditMode);
        document.getElementById("applyPasswordBtn").addEventListener("click", applyPasswordChange);
        document.getElementById("cancelPasswordBtn").addEventListener("click", cancelPasswordEdit);

        // 访问权限变化时的提示
        document.getElementById("accessLevelSelect").addEventListener("change", function() {
            const accessLevel = this.value;
            const passwordInput = document.getElementById("documentPasswordInput");

            if (accessLevel === "password_read" || accessLevel === "password_write") {
                showMessage("请设置文档访问密码", "info");
            }
        });

        // 自动保存
        let saveTimeout;
        function autoSave() {
            clearTimeout(saveTimeout);
            saveTimeout = setTimeout(saveDocument, 2000);
        }

        const titleInput = document.getElementById("titleInput");
        if (titleInput) {
            // 标题重名检查功能
            let titleCheckTimeout;
            titleInput.addEventListener("input", function() {
                const title = this.value.trim();
                const warningDiv = document.getElementById("titleWarning");

                // 清除之前的定时器
                if (titleCheckTimeout) {
                    clearTimeout(titleCheckTimeout);
                }

                // 如果标题为空，隐藏警告
                if (!title) {
                    warningDiv.classList.add("hidden");
                    autoSave(); // 仍然触发自动保存
                    return;
                }

                // 延迟检查，避免频繁请求
                titleCheckTimeout = setTimeout(async () => {
                    try {
                        const response = await apiCall("/api/admin/check-title", {
                            method: "POST",
                            body: JSON.stringify({
                                title: title,
                                excludeDocId: docId // 排除当前文档
                            })
                        });

                        const data = await response.json();

                        if (data.hasDuplication) {
                            const warningText = document.getElementById("titleWarningText");
                            if (data.count === 1) {
                                warningText.textContent = "已有1个文档使用此标题，建议使用更具体的标题";
                            } else {
                                warningText.textContent = "已有" + data.count + "个文档使用此标题，建议使用更具体的标题";
                            }
                            warningDiv.classList.remove("hidden");
                        } else {
                            warningDiv.classList.add("hidden");
                        }
                    } catch (error) {
                        // 检查失败时静默处理，不影响用户操作
                        console.log("Edit page - Title check failed:", error);
                        warningDiv.classList.add("hidden");
                    }
                }, 500); // 500ms延迟

                autoSave(); // 触发自动保存
            });
        }
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

// 404错误页面
function get404HTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>页面未找到 - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full card-modern p-8 text-center">
        <div class="mb-8">
            <div class="mb-6">
                <svg class="w-24 h-24 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
            </div>
            <div class="text-6xl font-bold text-gray-400 mb-4">404</div>
            <h1 class="text-3xl font-bold text-gray-800 mb-4">页面未找到</h1>
            <p class="text-gray-600 text-lg">抱歉，您访问的文档不存在或已过期。</p>
        </div>
        <div class="space-y-4">
            <a href="/" class="btn-base btn-primary w-full">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                </svg>
                返回首页
            </a>
        </div>
    </div>
</body>
</html>`;
}

// 阅后即焚访问冲突页面
function getBurnConflictHTML(errorMessage) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>文档访问冲突 - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full card-modern p-8 text-center">
        <div class="mb-8">
            <div class="mb-6">
                <svg class="w-24 h-24 mx-auto text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                </svg>
            </div>
            <h1 class="text-3xl font-bold text-gray-800 mb-4">文档正在被访问</h1>
            <p class="text-gray-600 text-lg">${escapeHtml(errorMessage)}</p>
        </div>
        <div class="space-y-4">
            <button onclick="window.location.reload()" class="btn-base btn-primary w-full">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                刷新重试
            </button>
            <a href="/" class="btn-base btn-secondary w-full">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                </svg>
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>访问文档：${escapeHtml(docTitle)} - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full card-modern p-8">
        <div class="text-center mb-8">
            <div class="mb-4">
                <svg class="w-16 h-16 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-gray-800 mb-3">访问受保护的文档</h1>
            <p class="text-gray-600 text-lg">${escapeHtml(docTitle)}</p>
        </div>

        <form id="passwordForm" class="space-y-6">
            <div>
                <label for="passwordInput" class="block text-sm font-semibold text-gray-700 mb-3">
                    请输入文档密码
                </label>
                <input type="password" id="passwordInput"
                       class="input-modern w-full"
                       placeholder="输入密码" required>
            </div>
            <button type="submit" class="btn-base btn-primary w-full">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path>
                </svg>
                访问文档
            </button>
        </form>

        <div id="errorMessage" class="mt-6 text-red-500 text-sm hidden"></div>

        <div class="mt-8 text-center">
            <a href="/" class="btn-icon" title="返回首页">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                </svg>
            </a>
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

// 阅后即焚倒计时页面
function getBurnCountdownHTML(document, permission) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>${escapeHtml(document.title)} - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen">
    <!-- 阅后即焚警告条 -->
    <div id="burnWarning" class="bg-red-500 text-white p-4 text-center font-semibold">
        <div class="flex items-center justify-center space-x-2">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
            </svg>
            <span>⚠️ 此文档为阅后即焚，将在 <span id="countdown">30</span> 秒后自动销毁</span>
        </div>
    </div>

    <header class="bg-white shadow-lg border-b border-gray-100">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center py-6 gap-4">
                <h1 class="text-3xl font-bold text-gray-900 text-center sm:text-left">${escapeHtml(document.title)}</h1>
                <div class="flex gap-1">
                    ${canWrite(permission) ? `
                    <a href="/edit/${encodeURIComponent(document.name || document.id)}" class="btn-icon btn-icon-primary" title="编辑文档">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                    </a>
                    ` : ''}
                    <a href="/" class="btn-icon btn-icon-secondary" title="返回首页">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                        </svg>
                    </a>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="card-modern p-8">
            <div class="prose prose-lg max-w-none">
                <pre class="whitespace-pre-wrap font-mono text-sm leading-relaxed bg-gray-50 p-6 rounded-lg border overflow-x-auto">${escapeHtml(document.content)}</pre>
            </div>
        </div>
    </main>

    <script>
        let timeLeft = 30;
        const countdownElement = document.getElementById('countdown');

        const timer = setInterval(() => {
            timeLeft--;
            countdownElement.textContent = timeLeft;

            if (timeLeft <= 0) {
                clearInterval(timer);
                document.getElementById('burnWarning').innerHTML = \`
                    <div class="flex items-center justify-center space-x-2">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                        </svg>
                        <span>🔥 文档正在销毁...</span>
                    </div>
                \`;

                // 调用后端API删除文档
                fetch('/api/burn-document/${escapeJavaScript(document.id)}', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }).then(() => {
                    // 删除成功后更新显示
                    document.getElementById('burnWarning').innerHTML = \`
                        <div class="flex items-center justify-center space-x-2">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                            <span>🔥 文档已销毁</span>
                        </div>
                    \`;

                    // 3秒后跳转到首页
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 3000);
                }).catch(error => {
                    console.error('删除文档失败:', error);
                    // 即使删除失败也跳转到首页
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 3000);
                });
            }
        }, 1000);
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>${escapeHtml(document.title)} - CF Notepad</title>
    <script src="https://cdn.tailwindcss.com"></script>
    ${getModernStyles()}
</head>
<body class="bg-gradient-modern min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-4xl mobile-compact-container">
        <!-- 头部信息 -->
        <div class="card-modern p-6 mb-8 mobile-compact-card mobile-compact-header">
            <div class="flex items-center justify-between gap-4">
                <div class="flex-1 min-w-0">
                    <h1 class="text-2xl font-bold text-gray-800 truncate">${escapeHtml(document.title)}</h1>
                </div>
                <div class="flex gap-1 flex-shrink-0">
                    ${canWrite(permission) ? `
                    <button id="editBtn" class="btn-icon btn-icon-primary" title="编辑文档">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                    </button>
                    <button id="saveBtn" style="display: none;" class="btn-icon btn-icon-success" title="保存文档">
                        <svg fill="currentColor" viewBox="0 0 24 24">
                            <path d="m20.71 9.29l-6-6a1 1 0 0 0-.32-.21A1.1 1.1 0 0 0 14 3H6a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3v-8a1 1 0 0 0-.29-.71M9 5h4v2H9Zm6 14H9v-3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1Zm4-1a1 1 0 0 1-1 1h-1v-3a3 3 0 0 0-3-3h-4a3 3 0 0 0-3 3v3H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h1v3a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V6.41l4 4Z"/>
                        </svg>
                    </button>
                    <button id="cancelBtn" style="display: none;" class="btn-icon" title="退出编辑">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                    ` : ''}
                    <button id="copyBtn" class="btn-icon btn-icon-primary" title="复制内容">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                        </svg>
                    </button>
                </div>
            </div>
        </div>

        <!-- 文档内容 -->
        <div class="card-modern p-6 mobile-compact-card">
            <div class="prose max-w-none">
                <!-- 查看模式 -->
                <pre id="documentContent" class="whitespace-pre-wrap font-mono text-sm bg-gray-50 p-6 rounded-xl border border-gray-200 overflow-x-auto leading-relaxed mobile-content-display">${escapeHtml(document.content)}</pre>

                <!-- 编辑模式 -->
                <div id="editMode" style="display: none;">
                    ${canAdmin(permission) ? `
                    <div class="mb-6">
                        <label class="block text-gray-700 text-sm font-semibold mb-3">文档标题</label>
                        <input type="text" id="titleInput" value="${escapeHtml(document.title)}"
                               class="input-modern w-full">
                    </div>
                    ` : ''}
                    <div class="mb-6">
                        <div class="flex items-center justify-between mb-3">
                            <label class="block text-gray-700 text-sm font-semibold">文档内容</label>
                            <!-- 状态消息 -->
                            <div id="statusMessage" class="text-sm text-gray-600 hidden"></div>
                        </div>
                        <textarea id="contentInput" rows="20"
                                  class="input-modern w-full font-mono text-sm leading-relaxed resize-y mobile-text-area"
                                  placeholder="请输入文档内容...">${escapeHtml(document.content)}</textarea>
                    </div>
                </div>
            </div>
        </div>

        <!-- 文档元信息 -->
        <div class="card-modern p-6 mt-6 mobile-compact-card">
            <div class="text-sm text-blue-600 space-y-2">
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    ${document.name ? `<div><span class="font-medium text-gray-700">文档名称:</span> <span class="text-blue-600">${escapeHtml(document.name)}</span></div>` : ''}
                    <div><span class="font-medium text-gray-700">创建时间:</span> <span class="text-blue-600">${new Date(document.createdAt).toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}</span></div>
                    <div><span class="font-medium text-gray-700">更新时间:</span> <span class="text-blue-600" data-update-time>${new Date(document.updatedAt).toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}</span></div>
                    <div><span class="font-medium text-gray-700">查看次数:</span> <span class="text-blue-600">${document.viewCount}</span></div>
                </div>
            </div>
        </div>

        <!-- 页脚信息 -->
        <div class="mt-6 text-center text-gray-500 text-sm">
            <p>CF Notepad - 安全、便捷的文档分享平台</p>
        </div>
    </div>

    <script>
        function showMessage(message, type) {
            const messageDiv = document.getElementById("statusMessage");

            let colorClass;
            let displayMessage = message;

            // 如果是保存成功消息，添加时间戳
            if (type === "success" && (message.includes("保存成功") || message.includes("自动保存"))) {
                const now = new Date();
                const timeStr = now.getHours().toString().padStart(2, '0') + ':' +
                               now.getMinutes().toString().padStart(2, '0') + ':' +
                               now.getSeconds().toString().padStart(2, '0');
                displayMessage = timeStr + ' ' + message;
            }

            messageDiv.textContent = displayMessage;

            switch(type) {
                case "success":
                    colorClass = "text-green-600";
                    break;
                case "error":
                    colorClass = "text-red-600";
                    break;
                case "info":
                    colorClass = "text-blue-600";
                    break;
                default:
                    colorClass = "text-gray-600";
            }

            messageDiv.className = \`text-sm \${colorClass}\`;
            messageDiv.classList.remove("hidden");

            setTimeout(() => {
                messageDiv.classList.add("hidden");
            }, 3000);
        }

        function copyContent() {
            const content = document.getElementById("documentContent").textContent;

            if (navigator.clipboard) {
                navigator.clipboard.writeText(content).then(function() {
                    showMessage("内容已复制到剪贴板", "info");
                }).catch(function() {
                    showMessage("复制失败，请手动选择并复制", "error");
                });
            } else {
                // 降级方案
                const textArea = document.createElement("textarea");
                textArea.value = content;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand("copy");
                    showMessage("内容已复制到剪贴板", "info");
                } catch (err) {
                    showMessage("复制失败，请手动选择并复制", "error");
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
            const titleInput = document.getElementById("titleInput");
            if (titleInput) {
                titleInput.value = originalTitle;
            }
            document.getElementById("contentInput").value = originalContent;
            exitEditMode();
        }

        async function saveDocument(isAutoSave = false) {
            const titleInput = document.getElementById("titleInput");
            const title = titleInput ? titleInput.value.trim() : originalTitle; // 如果没有标题输入框，使用原标题
            const content = document.getElementById("contentInput").value;

            // 对于访客模式，不验证标题（因为可能没有标题输入框）
            ${canAdmin(permission) ? `
            if (!title) {
                if (!isAutoSave) {
                    showMessage("请输入文档标题", "error");
                }
                return;
            }
            ` : ''}

            const saveBtn = document.getElementById("saveBtn");
            let originalIcon = null;

            if (!isAutoSave) {
                // 保存原始图标
                originalIcon = saveBtn.innerHTML;

                // 显示加载状态
                saveBtn.innerHTML = \`
                    <svg class="animate-spin" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z" opacity="0.3"/>
                        <path d="M12 2C13.1 2 14 2.9 14 4s-.9 2-2 2-2-.9-2-2 .9-2 2-2z"/>
                    </svg>
                \`;
                saveBtn.disabled = true;
                showMessage("保存中...", "info");
            }

            try {
                // 获取当前会话token
                const sessionToken = getCookie("sessionToken");

                // 构建请求数据，访客模式下不包含标题修改
                const requestData = { content };
                ${canAdmin(permission) ? `
                requestData.title = title;
                ` : ''}

                const response = await fetch(\`/api/public/documents/${encodeURIComponent(document.name || document.id)}\`, {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Session-Token": sessionToken
                    },
                    body: JSON.stringify(requestData)
                });

                const result = await response.json();

                if (response.ok) {
                    // 更新页面显示
                    ${canAdmin(permission) ? `
                    document.querySelector("h1").textContent = title;
                    ` : ''}
                    document.getElementById("documentContent").textContent = content;

                    // 更新原始值
                    ${canAdmin(permission) ? `
                    originalTitle = title;
                    ` : ''}
                    originalContent = content;

                    // 更新页面上的更新时间显示
                    const updateTimeElement = document.querySelector('[data-update-time]');
                    if (updateTimeElement) {
                        updateTimeElement.textContent = new Date().toLocaleString('zh-CN');
                    }

                    if (!isAutoSave) {
                        // 先显示保存成功消息
                        showMessage("保存成功", "success");

                        // 显示成功图标
                        saveBtn.innerHTML = \`
                            <svg fill="currentColor" viewBox="0 0 24 24">
                                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                        \`;

                        // 延迟退出编辑模式，确保用户能看到反馈
                        setTimeout(() => {
                            exitEditMode();
                            saveBtn.innerHTML = originalIcon;
                            saveBtn.disabled = false;
                        }, 1500);
                    } else {
                        // 自动保存成功时也显示简短提示
                        showMessage("自动保存", "success");
                    }
                } else {
                    if (!isAutoSave) {
                        showMessage(result.error || "保存失败，请重试", "error");
                        saveBtn.innerHTML = originalIcon;
                        saveBtn.disabled = false;
                    }
                }
            } catch (error) {
                if (!isAutoSave) {
                    showMessage("网络错误，请检查连接后重试", "error");
                    saveBtn.innerHTML = originalIcon;
                    saveBtn.disabled = false;
                }
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

        // 自动保存功能
        let saveTimeout;
        function autoSave() {
            clearTimeout(saveTimeout);
            saveTimeout = setTimeout(() => saveDocument(true), 2000);
        }

        ${canAdmin(permission) ? `
        document.getElementById("titleInput").addEventListener("input", autoSave);
        ` : ''}
        document.getElementById("contentInput").addEventListener("input", autoSave);
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

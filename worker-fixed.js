/**
 * Cloudflare Workers 网络粘贴板
 * 单文件架构，包含前后端所有代码
 */

// 配置常量
const CONFIG = {
  PASSWORD: 'CloudflareNotepad2024!', // 强密码，部署后请立即修改
  SESSION_DURATION: 24 * 60 * 60 * 1000, // 24小时会话时长
  DEFAULT_EXPIRY: 7 * 24 * 60 * 60 * 1000, // 默认7天过期
};

// 工具函数
function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function generateShareToken() {
  return 'share_' + Math.random().toString(36).substring(2, 15);
}

function isValidSession(sessionData) {
  if (!sessionData) return false;
  const session = JSON.parse(sessionData);
  return Date.now() - session.timestamp < CONFIG.SESSION_DURATION;
}

// 主要处理函数
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

  return new Response('Not Found', { status: 404 });
}

// API 处理函数
async function handleAPI(request, path, method) {
  const sessionToken = request.headers.get('X-Session-Token');
  
  // 登录接口不需要验证
  if (path === '/api/login' && method === 'POST') {
    return handleLogin(request);
  }

  // 分享接口不需要验证
  if (path.startsWith('/api/share/') && method === 'GET') {
    const shareToken = path.split('/')[3];
    return handleGetSharedDoc(shareToken);
  }

  // 其他接口需要验证会话
  const sessionData = sessionToken ? await NOTEPAD_KV.get('session_' + sessionToken) : null;
  if (!isValidSession(sessionData)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 路由分发
  if (path === '/api/documents' && method === 'GET') {
    return handleGetDocuments();
  }
  
  if (path === '/api/documents' && method === 'POST') {
    return handleCreateDocument(request);
  }
  
  if (path.startsWith('/api/documents/') && method === 'GET') {
    const docId = path.split('/')[3];
    return handleGetDocument(docId);
  }
  
  if (path.startsWith('/api/documents/') && method === 'PUT') {
    const docId = path.split('/')[3];
    return handleUpdateDocument(docId, request);
  }
  
  if (path.startsWith('/api/documents/') && method === 'DELETE') {
    const docId = path.split('/')[3];
    return handleDeleteDocument(docId);
  }

  if (path.startsWith('/api/documents/') && path.endsWith('/share') && method === 'POST') {
    const docId = path.split('/')[3];
    return handleCreateShare(docId);
  }

  return new Response('Not Found', { status: 404 });
}

// 登录处理
async function handleLogin(request) {
  const { password } = await request.json();
  
  if (password === CONFIG.PASSWORD) {
    const sessionToken = generateId();
    const sessionData = {
      timestamp: Date.now(),
      token: sessionToken
    };
    
    await NOTEPAD_KV.put('session_' + sessionToken, JSON.stringify(sessionData), {
      expirationTtl: CONFIG.SESSION_DURATION / 1000
    });
    
    return new Response(JSON.stringify({ 
      success: true, 
      sessionToken: sessionToken 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return new Response(JSON.stringify({
    success: false,
    error: '密码错误，请重试'
  }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 获取文档列表
async function handleGetDocuments() {
  const list = await NOTEPAD_KV.list({ prefix: 'doc_' });
  const documents = [];
  
  for (const key of list.keys) {
    const docData = await NOTEPAD_KV.get(key.name);
    if (docData) {
      const doc = JSON.parse(docData);
      documents.push({
        id: doc.id,
        title: doc.title,
        createdAt: doc.createdAt,
        updatedAt: doc.updatedAt,
        viewCount: doc.viewCount,
        expiresAt: doc.expiresAt
      });
    }
  }
  
  return new Response(JSON.stringify(documents), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// 创建文档
async function handleCreateDocument(request) {
  const { title, content, expiryDays } = await request.json();
  const docId = generateId();
  const now = Date.now();

  const expiryTime = expiryDays === -1 ? null : now + (expiryDays * 24 * 60 * 60 * 1000);

  const document = {
    id: docId,
    title: title || 'Untitled',
    content: content || '',
    createdAt: now,
    updatedAt: now,
    lastViewedAt: now,
    viewCount: 0,
    expiresAt: expiryTime
  };

  const ttl = expiryTime ? Math.floor((expiryTime - now) / 1000) : undefined;
  await NOTEPAD_KV.put('doc_' + docId, JSON.stringify(document), ttl ? { expirationTtl: ttl } : {});

  return new Response(JSON.stringify(document), {
    headers: { 'Content-Type': 'application/json' }
  });
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

// 删除文档
async function handleDeleteDocument(docId) {
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
  return '<!DOCTYPE html>' +
    '<html lang="zh-CN">' +
    '<head>' +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>云端粘贴板</title>' +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    '</head>' +
    '<body class="bg-gray-100 min-h-screen">' +

    '<!-- 登录模态框 -->' +
    '<div id="loginModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">' +
    '<div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">' +
    '<h2 class="text-2xl font-bold mb-6 text-center text-gray-800">登录验证</h2>' +
    '<form id="loginForm">' +
    '<div class="mb-4">' +
    '<label class="block text-gray-700 text-sm font-bold mb-2">密码</label>' +
    '<input type="password" id="passwordInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>' +
    '</div>' +
    '<button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">' +
    '登录' +
    '</button>' +
    '</form>' +
    '<div id="loginError" class="mt-4 text-red-500 text-sm hidden"></div>' +
    '</div>' +
    '</div>' +

    '<!-- 主界面 -->' +
    '<div id="mainApp" class="hidden">' +
    '<header class="bg-white shadow-sm">' +
    '<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">' +
    '<div class="flex justify-between items-center py-6">' +
    '<h1 class="text-3xl font-bold text-gray-900">云端粘贴板</h1>' +
    '<button id="logoutBtn" class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">' +
    '退出登录' +
    '</button>' +
    '</div>' +
    '</div>' +
    '</header>' +

    '<main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">' +
    '<div class="px-4 py-6 sm:px-0">' +

    '<!-- 创建新文档按钮 -->' +
    '<div class="mb-6">' +
    '<button id="createDocBtn" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">' +
    '+ 创建新文档' +
    '</button>' +
    '</div>' +

    '<!-- 文档列表 -->' +
    '<div class="bg-white shadow overflow-hidden sm:rounded-md">' +
    '<div class="px-4 py-5 sm:p-6">' +
    '<h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">我的文档</h3>' +
    '<div id="documentsList" class="space-y-3">' +
    '<!-- 文档列表将在这里动态加载 -->' +
    '</div>' +
    '</div>' +
    '</div>' +

    '</div>' +
    '</main>' +
    '</div>' +

    '<!-- 创建文档模态框 -->' +
    '<div id="createModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">' +
    '<div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">' +
    '<h2 class="text-2xl font-bold mb-6 text-center text-gray-800">创建新文档</h2>' +
    '<form id="createForm">' +
    '<div class="mb-4">' +
    '<label class="block text-gray-700 text-sm font-bold mb-2">文档标题</label>' +
    '<input type="text" id="titleInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>' +
    '</div>' +
    '<div class="mb-4">' +
    '<label class="block text-gray-700 text-sm font-bold mb-2">过期时间</label>' +
    '<select id="expirySelect" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">' +
    '<option value="1">1天</option>' +
    '<option value="7" selected>7天</option>' +
    '<option value="30">30天</option>' +
    '<option value="-1">永久</option>' +
    '</select>' +
    '</div>' +
    '<div class="flex space-x-4">' +
    '<button type="submit" class="flex-1 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">' +
    '创建' +
    '</button>' +
    '<button type="button" id="cancelCreateBtn" class="flex-1 bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">' +
    '取消' +
    '</button>' +
    '</div>' +
    '</form>' +
    '</div>' +
    '</div>' +

    getMainScript() +
    '</body>' +
    '</html>';
}

// 主页面JavaScript代码
function getMainScript() {
  return '<script>' +
    'let sessionToken = localStorage.getItem("sessionToken");' +

    '// 检查会话状态' +
    'function checkSession() {' +
    'console.log("检查会话状态, sessionToken:", sessionToken);' +
    'if (sessionToken) {' +
    'console.log("会话有效，显示主应用");' +
    'document.getElementById("loginModal").classList.add("hidden");' +
    'document.getElementById("mainApp").classList.remove("hidden");' +
    'loadDocuments();' +
    '} else {' +
    'console.log("无会话，显示登录界面");' +
    'document.getElementById("loginModal").classList.remove("hidden");' +
    'document.getElementById("mainApp").classList.add("hidden");' +
    '}' +
    '}' +

    '// 登录处理' +
    'document.getElementById("loginForm").addEventListener("submit", async function(e) {' +
    'e.preventDefault();' +
    'console.log("登录表单提交");' +
    'const password = document.getElementById("passwordInput").value;' +
    'const errorDiv = document.getElementById("loginError");' +
    'console.log("输入的密码长度:", password.length);' +

    'try {' +
    'const response = await fetch("/api/login", {' +
    'method: "POST",' +
    'headers: { "Content-Type": "application/json" },' +
    'body: JSON.stringify({ password: password })' +
    '});' +

    'const result = await response.json();' +
    'if (response.ok && result.success) {' +
    'sessionToken = result.sessionToken;' +
    'localStorage.setItem("sessionToken", sessionToken);' +
    'document.cookie = "sessionToken=" + sessionToken + "; path=/; max-age=86400";' +
    'errorDiv.classList.add("hidden");' +
    'checkSession();' +
    '} else {' +
    'errorDiv.textContent = result.error || "密码错误，请重试";' +
    'errorDiv.classList.remove("hidden");' +
    '}' +
    '} catch (error) {' +
    'console.error("Login error:", error);' +
    'errorDiv.textContent = "登录失败，请重试";' +
    'errorDiv.classList.remove("hidden");' +
    '}' +
    '});' +

    '// 退出登录' +
    'document.getElementById("logoutBtn").addEventListener("click", function() {' +
    'sessionToken = null;' +
    'localStorage.removeItem("sessionToken");' +
    'document.cookie = "sessionToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";' +
    'checkSession();' +
    '});' +

    '// 创建文档按钮' +
    'document.getElementById("createDocBtn").addEventListener("click", function() {' +
    'document.getElementById("createModal").classList.remove("hidden");' +
    '});' +

    '// 取消创建' +
    'document.getElementById("cancelCreateBtn").addEventListener("click", function() {' +
    'document.getElementById("createModal").classList.add("hidden");' +
    'document.getElementById("titleInput").value = "";' +
    '});' +

    '// 创建文档表单提交' +
    'document.getElementById("createForm").addEventListener("submit", async function(e) {' +
    'e.preventDefault();' +
    'const title = document.getElementById("titleInput").value;' +
    'const expiryDays = parseInt(document.getElementById("expirySelect").value);' +

    'try {' +
    'const response = await fetch("/api/documents", {' +
    'method: "POST",' +
    'headers: {' +
    '"Content-Type": "application/json",' +
    '"X-Session-Token": sessionToken' +
    '},' +
    'body: JSON.stringify({ title: title, content: "", expiryDays: expiryDays })' +
    '});' +

    'const result = await response.json();' +
    'if (response.ok) {' +
    'document.getElementById("createModal").classList.add("hidden");' +
    'document.getElementById("titleInput").value = "";' +
    'window.location.href = "/edit/" + result.id;' +
    '} else {' +
    'alert("创建文档失败：" + result.error);' +
    '}' +
    '} catch (error) {' +
    'alert("创建文档失败，请重试");' +
    '}' +
    '});' +

    '// 加载文档列表' +
    'async function loadDocuments() {' +
    'try {' +
    'const response = await fetch("/api/documents", {' +
    'headers: { "X-Session-Token": sessionToken }' +
    '});' +

    'if (response.status === 401) {' +
    'sessionToken = null;' +
    'localStorage.removeItem("sessionToken");' +
    'checkSession();' +
    'return;' +
    '}' +

    'const documents = await response.json();' +
    'const listContainer = document.getElementById("documentsList");' +
    'listContainer.innerHTML = "";' +

    'if (documents.length === 0) {' +
    'listContainer.innerHTML = "<p class=\\"text-gray-500\\">暂无文档，点击上方按钮创建新文档</p>";' +
    'return;' +
    '}' +

    'documents.forEach(function(doc) {' +
    'const docElement = createDocumentElement(doc);' +
    'listContainer.appendChild(docElement);' +
    '});' +
    '} catch (error) {' +
    'console.error("加载文档失败:", error);' +
    '}' +
    '}' +

    '// 创建文档元素' +
    'function createDocumentElement(doc) {' +
    'const div = document.createElement("div");' +
    'div.className = "border border-gray-200 rounded-lg p-4 hover:bg-gray-50";' +

    'const createdDate = new Date(doc.createdAt).toLocaleString("zh-CN");' +
    'const updatedDate = new Date(doc.updatedAt).toLocaleString("zh-CN");' +
    'const expiresText = doc.expiresAt ? new Date(doc.expiresAt).toLocaleString("zh-CN") : "永久";' +

    'div.innerHTML = ' +
    '"<div class=\\"flex justify-between items-start\\">" +' +
    '"<div class=\\"flex-1\\">" +' +
    '"<h4 class=\\"text-lg font-medium text-gray-900 mb-2\\">" + doc.title + "</h4>" +' +
    '"<div class=\\"text-sm text-gray-500 space-y-1\\">" +' +
    '"<p>创建时间：" + createdDate + "</p>" +' +
    '"<p>更新时间：" + updatedDate + "</p>" +' +
    '"<p>查看次数：" + doc.viewCount + "</p>" +' +
    '"<p>过期时间：" + expiresText + "</p>" +' +
    '"</div>" +' +
    '"</div>" +' +
    '"<div class=\\"flex space-x-2\\">" +' +
    '"<button onclick=\\"editDocument(\'" + doc.id + "\')\\" class=\\"bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 px-3 rounded text-sm\\">编辑</button>" +' +
    '"<button onclick=\\"shareDocument(\'" + doc.id + "\')\\" class=\\"bg-green-500 hover:bg-green-700 text-white font-bold py-1 px-3 rounded text-sm\\">分享</button>" +' +
    '"<button onclick=\\"deleteDocument(\'" + doc.id + "\')\\" class=\\"bg-red-500 hover:bg-red-700 text-white font-bold py-1 px-3 rounded text-sm\\">删除</button>" +' +
    '"</div>" +' +
    '"</div>";' +

    'return div;' +
    '}' +

    '// 编辑文档' +
    'function editDocument(docId) {' +
    'window.location.href = "/edit/" + docId;' +
    '}' +

    '// 分享文档' +
    'async function shareDocument(docId) {' +
    'try {' +
    'const response = await fetch("/api/documents/" + docId + "/share", {' +
    'method: "POST",' +
    'headers: { "X-Session-Token": sessionToken }' +
    '});' +

    'const result = await response.json();' +
    'if (response.ok) {' +
    'const shareUrl = window.location.origin + result.shareUrl;' +
    'showShareModal(shareUrl);' +
    '} else {' +
    'alert("创建分享链接失败：" + result.error);' +
    '}' +
    '} catch (error) {' +
    'alert("创建分享链接失败，请重试");' +
    '}' +
    '}' +

    '// 删除文档' +
    'async function deleteDocument(docId) {' +
    'if (!confirm("确定要删除这个文档吗？此操作不可撤销。")) return;' +

    'try {' +
    'const response = await fetch("/api/documents/" + docId, {' +
    'method: "DELETE",' +
    'headers: { "X-Session-Token": sessionToken }' +
    '});' +

    'if (response.ok) {' +
    'loadDocuments();' +
    '} else {' +
    'alert("删除文档失败");' +
    '}' +
    '} catch (error) {' +
    'alert("删除文档失败，请重试");' +
    '}' +
    '}' +

    '// 显示分享模态框' +
    'function showShareModal(shareUrl) {' +
    'const modal = document.createElement("div");' +
    'modal.className = "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50";' +
    'modal.innerHTML = ' +
    '"<div class=\\"bg-white rounded-lg p-8 max-w-md w-full mx-4\\">" +' +
    '"<h2 class=\\"text-2xl font-bold mb-6 text-center text-gray-800\\">分享文档</h2>" +' +
    '"<div class=\\"mb-6\\">" +' +
    '"<label class=\\"block text-gray-700 text-sm font-bold mb-2\\">分享链接</label>" +' +
    '"<div class=\\"flex\\">" +' +
    '"<input type=\\"text\\" id=\\"shareUrlInput\\" value=\\"" + shareUrl + "\\" class=\\"flex-1 px-3 py-2 border border-gray-300 rounded-l-md\\" readonly>" +' +
    '"<button onclick=\\"copyShareUrl()\\" class=\\"bg-blue-500 hover:bg-blue-700 text-white px-4 py-2 rounded-r-md\\">复制</button>" +' +
    '"</div>" +' +
    '"</div>" +' +
    '"<div class=\\"text-sm text-gray-600 mb-6\\">" +' +
    '"<p>• 分享链接为只读模式，无需密码即可访问</p>" +' +
    '"<p>• 链接将保持有效直到原文档被删除</p>" +' +
    '"</div>" +' +
    '"<div class=\\"flex space-x-4\\">" +' +
    '"<button onclick=\\"openShareUrl()\\" class=\\"flex-1 bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded\\">预览</button>" +' +
    '"<button onclick=\\"closeShareModal()\\" class=\\"flex-1 bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded\\">关闭</button>" +' +
    '"</div>" +' +
    '"</div>";' +

    'document.body.appendChild(modal);' +

    'window.copyShareUrl = function() {' +
    'const input = document.getElementById("shareUrlInput");' +
    'input.select();' +
    'try {' +
    'document.execCommand("copy");' +
    'alert("链接已复制到剪贴板");' +
    '} catch (err) {' +
    'navigator.clipboard.writeText(shareUrl).then(function() {' +
    'alert("链接已复制到剪贴板");' +
    '}).catch(function() {' +
    'alert("复制失败，请手动复制");' +
    '});' +
    '}' +
    '};' +

    'window.openShareUrl = function() {' +
    'window.open(shareUrl, "_blank");' +
    '};' +

    'window.closeShareModal = function() {' +
    'document.body.removeChild(modal);' +
    'delete window.copyShareUrl;' +
    'delete window.openShareUrl;' +
    'delete window.closeShareModal;' +
    '};' +
    '}' +

    '// 复制到剪贴板' +
    'function copyToClipboard(text) {' +
    'navigator.clipboard.writeText(text).then(function() {' +
    'alert("链接已复制到剪贴板");' +
    '}).catch(function() {' +
    'alert("复制失败，请手动复制");' +
    '});' +
    '}' +

    '// 初始化' +
    'checkSession();' +
    '</script>';
}

// 编辑页面HTML
function getEditHTML(docId) {
  return '<!DOCTYPE html>' +
    '<html lang="zh-CN">' +
    '<head>' +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>编辑文档 - 云端粘贴板</title>' +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    '</head>' +
    '<body class="bg-gray-100 min-h-screen">' +

    '<header class="bg-white shadow-sm">' +
    '<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">' +
    '<div class="flex justify-between items-center py-6">' +
    '<h1 class="text-3xl font-bold text-gray-900">编辑文档</h1>' +
    '<div class="flex space-x-4">' +
    '<button id="saveBtn" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">' +
    '保存' +
    '</button>' +
    '<a href="/" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">' +
    '返回首页' +
    '</a>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</header>' +

    '<main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">' +
    '<div class="px-4 py-6 sm:px-0">' +

    '<div class="bg-white shadow sm:rounded-lg">' +
    '<div class="px-4 py-5 sm:p-6">' +

    '<!-- 文档标题 -->' +
    '<div class="mb-6">' +
    '<label class="block text-sm font-medium text-gray-700 mb-2">文档标题</label>' +
    '<input type="text" id="titleInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">' +
    '</div>' +

    '<!-- 文档内容 -->' +
    '<div class="mb-6">' +
    '<label class="block text-sm font-medium text-gray-700 mb-2">文档内容</label>' +
    '<textarea id="contentTextarea" rows="20" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"></textarea>' +
    '</div>' +

    '<!-- 文档信息 -->' +
    '<div id="docInfo" class="text-sm text-gray-500 space-y-1">' +
    '<!-- 文档信息将在这里显示 -->' +
    '</div>' +

    '</div>' +
    '</div>' +

    '</div>' +
    '</main>' +

    getEditScript(docId) +
    '</body>' +
    '</html>';
}

// 编辑页面JavaScript
function getEditScript(docId) {
  return '<script>' +
    'const docId = "' + docId + '";' +
    'const sessionToken = localStorage.getItem("sessionToken");' +
    'let currentDoc = null;' +

    '// 检查登录状态' +
    'if (!sessionToken) {' +
    'window.location.href = "/";' +
    '}' +

    '// 加载文档' +
    'async function loadDocument() {' +
    'try {' +
    'const response = await fetch("/api/documents/" + docId, {' +
    'headers: { "X-Session-Token": sessionToken }' +
    '});' +

    'if (response.status === 401) {' +
    'localStorage.removeItem("sessionToken");' +
    'window.location.href = "/";' +
    'return;' +
    '}' +

    'if (response.status === 404) {' +
    'alert("文档不存在");' +
    'window.location.href = "/";' +
    'return;' +
    '}' +

    'currentDoc = await response.json();' +
    'document.getElementById("titleInput").value = currentDoc.title;' +
    'document.getElementById("contentTextarea").value = currentDoc.content;' +
    'updateDocInfo();' +
    '} catch (error) {' +
    'alert("加载文档失败");' +
    'window.location.href = "/";' +
    '}' +
    '}' +

    '// 更新文档信息显示' +
    'function updateDocInfo() {' +
    'if (!currentDoc) return;' +

    'const createdDate = new Date(currentDoc.createdAt).toLocaleString("zh-CN");' +
    'const updatedDate = new Date(currentDoc.updatedAt).toLocaleString("zh-CN");' +
    'const expiresText = currentDoc.expiresAt ? new Date(currentDoc.expiresAt).toLocaleString("zh-CN") : "永久";' +

    'document.getElementById("docInfo").innerHTML = ' +
    '"<p>创建时间：" + createdDate + "</p>" +' +
    '"<p>更新时间：" + updatedDate + "</p>" +' +
    '"<p>查看次数：" + currentDoc.viewCount + "</p>" +' +
    '"<p>过期时间：" + expiresText + "</p>";' +
    '}' +

    '// 保存文档' +
    'async function saveDocument() {' +
    'const title = document.getElementById("titleInput").value;' +
    'const content = document.getElementById("contentTextarea").value;' +

    'if (!title.trim()) {' +
    'alert("请输入文档标题");' +
    'return;' +
    '}' +

    'try {' +
    'const response = await fetch("/api/documents/" + docId, {' +
    'method: "PUT",' +
    'headers: {' +
    '"Content-Type": "application/json",' +
    '"X-Session-Token": sessionToken' +
    '},' +
    'body: JSON.stringify({ title: title, content: content })' +
    '});' +

    'if (response.ok) {' +
    'currentDoc = await response.json();' +
    'updateDocInfo();' +
    'alert("保存成功");' +
    '} else {' +
    'const result = await response.json();' +
    'alert("保存失败：" + result.error);' +
    '}' +
    '} catch (error) {' +
    'alert("保存失败，请重试");' +
    '}' +
    '}' +

    '// 绑定事件' +
    'document.getElementById("saveBtn").addEventListener("click", saveDocument);' +

    '// 快捷键保存 (Ctrl+S)' +
    'document.addEventListener("keydown", function(e) {' +
    'if (e.ctrlKey && e.key === "s") {' +
    'e.preventDefault();' +
    'saveDocument();' +
    '}' +
    '});' +

    '// 初始化' +
    'loadDocument();' +
    '</script>';
}

// 分享页面HTML
function getShareHTML(shareToken) {
  return '<!DOCTYPE html>' +
    '<html lang="zh-CN">' +
    '<head>' +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>分享文档 - 云端粘贴板</title>' +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    '</head>' +
    '<body class="bg-gray-100 min-h-screen">' +

    '<header class="bg-white shadow-sm">' +
    '<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">' +
    '<div class="flex justify-between items-center py-6">' +
    '<h1 class="text-3xl font-bold text-gray-900">分享文档</h1>' +
    '<div class="flex space-x-4">' +
    '<button id="copyBtn" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">' +
    '复制内容' +
    '</button>' +
    '<a href="/" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">' +
    '访问主页' +
    '</a>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</header>' +

    '<main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">' +
    '<div class="px-4 py-6 sm:px-0">' +

    '<div class="bg-white shadow sm:rounded-lg">' +
    '<div class="px-4 py-5 sm:p-6">' +

    '<!-- 文档标题 -->' +
    '<div class="mb-6">' +
    '<h2 id="docTitle" class="text-2xl font-bold text-gray-900"></h2>' +
    '</div>' +

    '<!-- 文档内容 -->' +
    '<div class="mb-6">' +
    '<div class="bg-gray-50 border border-gray-200 rounded-md p-4">' +
    '<pre id="docContent" class="whitespace-pre-wrap font-mono text-sm text-gray-800"></pre>' +
    '</div>' +
    '</div>' +

    '<!-- 文档信息 -->' +
    '<div id="docInfo" class="text-sm text-gray-500 space-y-1 border-t pt-4">' +
    '<!-- 文档信息将在这里显示 -->' +
    '</div>' +

    '</div>' +
    '</div>' +

    '</div>' +
    '</main>' +

    getShareScript(shareToken) +
    '</body>' +
    '</html>';
}

// 分享页面JavaScript
function getShareScript(shareToken) {
  return '<script>' +
    'const shareToken = "' + shareToken + '";' +
    'let currentDoc = null;' +

    '// 加载分享文档' +
    'async function loadSharedDocument() {' +
    'try {' +
    'const response = await fetch("/api/share/" + shareToken);' +

    'if (response.status === 404) {' +
    'document.getElementById("docTitle").textContent = "文档不存在";' +
    'document.getElementById("docContent").textContent = "该分享链接无效或文档已被删除。";' +
    'return;' +
    '}' +

    'currentDoc = await response.json();' +
    'document.getElementById("docTitle").textContent = currentDoc.title;' +
    'document.getElementById("docContent").textContent = currentDoc.content;' +
    'updateDocInfo();' +
    '} catch (error) {' +
    'document.getElementById("docTitle").textContent = "加载失败";' +
    'document.getElementById("docContent").textContent = "无法加载文档内容，请稍后重试。";' +
    '}' +
    '}' +

    '// 更新文档信息显示' +
    'function updateDocInfo() {' +
    'if (!currentDoc) return;' +

    'const createdDate = new Date(currentDoc.createdAt).toLocaleString("zh-CN");' +
    'const updatedDate = new Date(currentDoc.updatedAt).toLocaleString("zh-CN");' +

    'document.getElementById("docInfo").innerHTML = ' +
    '"<p><strong>创建时间：</strong>" + createdDate + "</p>" +' +
    '"<p><strong>更新时间：</strong>" + updatedDate + "</p>" +' +
    '"<p class=\\"text-xs text-gray-400 mt-2\\">此文档为只读模式，无法编辑</p>";' +
    '}' +

    '// 复制文档内容' +
    'function copyContent() {' +
    'if (!currentDoc) {' +
    'alert("没有可复制的内容");' +
    'return;' +
    '}' +

    'navigator.clipboard.writeText(currentDoc.content).then(function() {' +
    'alert("内容已复制到剪贴板");' +
    '}).catch(function() {' +
    'alert("复制失败，请手动选择并复制");' +
    '});' +
    '}' +

    '// 绑定事件' +
    'document.getElementById("copyBtn").addEventListener("click", copyContent);' +

    '// 初始化' +
    'loadSharedDocument();' +
    '</script>';
}

/**
 * Cloudflare Workers 网络粘贴板 - 修复版本
 * 使用模板字符串避免复杂的字符串拼接问题
 */

// 配置常量
const CONFIG = {
  PASSWORD: 'CloudflareNotepad2024!',
  SESSION_DURATION: 24 * 60 * 60 * 1000,
  DEFAULT_EXPIRY: 7 * 24 * 60 * 60 * 1000,
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
        <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
            <h2 class="text-2xl font-bold mb-6 text-center text-gray-800">创建新文档</h2>
            <form id="createForm">
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">文档标题</label>
                    <input type="text" id="titleInput" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                </div>
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2">过期时间</label>
                    <select id="expirySelect" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value="1">1天</option>
                        <option value="7" selected>7天</option>
                        <option value="30">30天</option>
                        <option value="-1">永久</option>
                    </select>
                </div>
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

        return response;
    }

    async function loadDocuments() {
        try {
            const response = await apiCall("/api/documents");
            const documents = await response.json();

            const listElement = document.getElementById("documentsList");
            if (documents.length === 0) {
                listElement.innerHTML = '<p class="text-gray-500">暂无文档，点击上方按钮创建第一个文档</p>';
                return;
            }

            listElement.innerHTML = documents.map(doc => {
                const createdDate = new Date(doc.createdAt).toLocaleString();
                const updatedDate = new Date(doc.updatedAt).toLocaleString();
                const expiryText = doc.expiresAt ? new Date(doc.expiresAt).toLocaleString() : "永久";

                return \`
                    <div class="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                        <div class="flex justify-between items-start">
                            <div class="flex-1">
                                <h4 class="text-lg font-medium text-gray-900 mb-2">\${doc.title}</h4>
                                <div class="text-sm text-gray-500 space-y-1">
                                    <p>创建时间: \${createdDate}</p>
                                    <p>更新时间: \${updatedDate}</p>
                                    <p>查看次数: \${doc.viewCount}</p>
                                    <p>过期时间: \${expiryText}</p>
                                </div>
                            </div>
                            <div class="flex space-x-2 ml-4">
                                <button onclick="editDocument('\${doc.id}')" class="bg-blue-500 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                                    查看
                                </button>
                                <button onclick="shareDocument('\${doc.id}')" class="bg-green-500 hover:bg-green-700 text-white px-3 py-1 rounded text-sm">
                                    分享
                                </button>
                                <button onclick="deleteDocument('\${doc.id}')" class="bg-red-500 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
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
            const response = await apiCall(\`/api/documents/\${docId}/share\`, {
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
            await apiCall(\`/api/documents/\${docId}\`, {
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
            const response = await fetch("/api/login", {
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

    document.getElementById("createForm").addEventListener("submit", async function(e) {
        e.preventDefault();
        const title = document.getElementById("titleInput").value;
        const expiryDays = parseInt(document.getElementById("expirySelect").value);

        try {
            const response = await apiCall("/api/documents", {
                method: "POST",
                body: JSON.stringify({
                    title: title,
                    content: "",
                    expiryDays: expiryDays
                })
            });

            const newDoc = await response.json();
            document.getElementById("createModal").classList.add("hidden");
            document.getElementById("titleInput").value = "";
            window.location.href = "/edit/" + newDoc.id;
        } catch (error) {
            alert("创建文档失败: " + error.message);
        }
    });

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
        const docId = "${docId}";
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

            return response;
        }

        async function loadDocument() {
            try {
                const response = await apiCall(\`/api/documents/\${docId}\`);
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
                const response = await apiCall(\`/api/documents/\${docId}\`, {
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
                const response = await apiCall(\`/api/documents/\${docId}/share\`, {
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
        const shareToken = "${shareToken}";

        async function loadSharedDocument() {
            try {
                const response = await fetch(\`/api/share/\${shareToken}\`);
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

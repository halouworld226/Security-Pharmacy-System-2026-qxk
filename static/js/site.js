/**
 * CSRF Token 前端集成
 * 为所有表单自动添加隐藏 CSRF 字段，为 AJAX 请求自动添加 X-CSRF-Token 头
 */

function getCSRFToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

document.addEventListener('DOMContentLoaded', function() {
    var token = getCSRFToken();
    if (!token) return;

    // 为所有非 GET 表单自动添加隐藏 CSRF 字段
    document.querySelectorAll('form').forEach(function(form) {
        var method = (form.getAttribute('method') || 'get').toUpperCase();
        if (method !== 'GET' && !form.querySelector('input[name="csrf_token"]')) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'csrf_token';
            input.value = token;
            form.appendChild(input);
        }
    });
});

// jQuery AJAX 全局拦截器
if (typeof $ !== 'undefined') {
    $(document).ajaxSend(function(event, xhr, settings) {
        if (settings.type && settings.type.toUpperCase() !== 'GET') {
            var token = getCSRFToken();
            if (token) {
                xhr.setRequestHeader('X-CSRF-Token', token);
            }
        }
    });
}

// 原生 fetch 拦截器：为所有非 GET 请求自动添加 X-CSRF-Token 头
(function() {
    var originalFetch = window.fetch;
    window.fetch = function(url, options) {
        options = options || {};
        var method = (options.method || 'GET').toUpperCase();
        if (method !== 'GET') {
            options.headers = options.headers || {};
            if (!options.headers['X-CSRF-Token']) {
                options.headers['X-CSRF-Token'] = getCSRFToken();
            }
        }
        return originalFetch.call(this, url, options);
    };
})();

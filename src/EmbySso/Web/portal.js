(() => {
    'use strict'
    const data = JSON.parse(document.getElementById('bootstrap').textContent)
    const gate = document.getElementById('gate')
    const panel = document.getElementById('code-panel')
    const action = document.getElementById('gate-action')
    const button = document.getElementById('refresh-code')
    let expiry

    function deny(title, message, target) {
        clearTimeout(expiry)
        document.getElementById('login-code').textContent = ''
        panel.hidden = true
        gate.hidden = false
        document.getElementById('gate-title').textContent = title
        document.getElementById('error-message').textContent = message
        action.href = target || data.publicUrl + '/web/index.html'
        action.textContent = target && target.includes('settings/profile.html') ? '前往个人配置' : '返回 Emby'
        action.hidden = false
    }

    async function generate() {
        button.disabled = true
        clearTimeout(expiry)
        document.getElementById('login-code').textContent = ''
        try {
            const info = await fetch(data.publicUrl + '/System/Info/Public', { credentials: 'same-origin' })
            if (!info.ok) throw new Error('无法连接 Emby，请稍后刷新页面重试。')
            const serverInfo = await info.json()
            const credentials = JSON.parse(localStorage.getItem('servercredentials3') || '{}')
            const server = (credentials.Servers || []).find(item => item.Id === serverInfo.Id)
            const user = (server?.Users || []).find(item => item.UserId === server.UserId)
            const token = user?.AccessToken || server?.AccessToken
            if (!server?.UserId || !token) {
                deny('禁止访问', '你尚未登录 Emby。请先在 Emby 中登录，再打开此页面。')
                return
            }
            const response = await fetch(data.publicUrl + '/sso/code', {
                method: 'POST', credentials: 'same-origin', headers: { 'X-Emby-Token': token }
            })
            if (response.status === 401) {
                deny('禁止访问', '当前登录会话已失效，请重新登录 Emby 后再打开此页面。')
                return
            }
            if (!response.ok) {
                const error = new DOMParser().parseFromString(await response.text(), 'text/html')
                deny(error.querySelector('h1')?.textContent || '禁止访问',
                    error.querySelector('#error-message')?.textContent || '当前账号无法访问此页面。',
                    error.querySelector('#error-action')?.getAttribute('href'))
                return
            }
            const code = await response.json()
            document.getElementById('username').textContent = code.username
            document.getElementById('login-code').textContent = code.loginCode
            document.getElementById('expiry').textContent = '5 分钟内有效，仅可使用一次。重新生成后旧码立即失效。'
            gate.hidden = true
            panel.hidden = false
            expiry = setTimeout(() => {
                document.getElementById('login-code').textContent = '已过期'
                document.getElementById('expiry').textContent = '请重新生成 PIN 码后使用。'
            }, 5 * 60 * 1000)
        } catch (error) {
            deny('无法获取 PIN 码', error.message || '请刷新页面重试。')
        } finally {
            button.disabled = false
        }
    }

    button.addEventListener('click', generate)
    window.addEventListener('pagehide', () => {
        clearTimeout(expiry)
        document.getElementById('login-code').textContent = ''
    })
    window.addEventListener('pageshow', event => {
        if (event.persisted) location.reload()
    })
    generate()
})()

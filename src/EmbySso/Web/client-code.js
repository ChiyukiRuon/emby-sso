(() => {
    'use strict'
    history.replaceState(null, '', location.pathname)
    const bootstrap = document.getElementById('bootstrap')
    const data = JSON.parse(bootstrap.textContent)
    bootstrap.remove()
    document.getElementById('username').textContent = data.username
    document.getElementById('login-code').textContent = data.loginCode
    setTimeout(() => {
        document.getElementById('login-code').textContent = '已过期'
        document.getElementById('expiry').textContent = '请返回重新获取登录码。'
    }, 5 * 60 * 1000)
    window.addEventListener('pagehide', () => {
        document.getElementById('login-code').textContent = ''
    })
    window.addEventListener('pageshow', event => {
        if (event.persisted) location.replace(document.querySelector('a').href)
    })
})()

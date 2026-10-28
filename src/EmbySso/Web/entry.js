/* Emby login entry and personal profile binding controls. */
(() => {
    'use strict'

    function siteBase() {
        var path = location.pathname
        var marker = '/web/index.html'
        if (path.endsWith(marker)) return path.slice(0, -marker.length)
        if (path.endsWith('/web/')) return path.slice(0, -'/web/'.length)
        if (path.endsWith('/web')) return path.slice(0, -'/web'.length)
        return ''
    }

    function isLoginPage() {
        return /\/startup\/(?:login|manuallogin)\.html/i.test(location.hash || '')
    }

    var button = null
    var passwordCheckKey = ''
    var passwordCheckPending = false

    async function ensurePasswordReminder() {
        if (isLoginPage() || !window.ApiClient || !ApiClient.getCurrentUserId()) {
            passwordCheckKey = ''
            return
        }
        var client = window.ApiClient
        var userId = client.getCurrentUserId()
        var token = client.accessToken()
        var route = location.hash
        var key = token + route
        if (!token || passwordCheckPending || passwordCheckKey === key || !window.Emby) return
        var splash = document.querySelector('.app-splash-container')
        if (splash && splash.getClientRects().length && getComputedStyle(splash).display !== 'none') return
        passwordCheckPending = true
        function isCurrent() {
            return window.ApiClient === client && client.getCurrentUserId() === userId &&
                client.accessToken() === token && location.hash === route
        }
        try {
            var response = await fetch(siteBase() + '/sso/password-status', {
                credentials: 'same-origin', headers: { 'X-Emby-Token': token }
            })
            if (!response.ok) return
            var state = await response.json()
            if (!isCurrent()) return
            if (!state.requiresPasswordChange) {
                passwordCheckKey = key
                return
            }
            var alert = await Emby.importModule('./modules/common/dialogs/alert.js')
            if (!isCurrent()) return
            passwordCheckKey = key
            await alert({ title: '请修改本地密码',
                text: '你的账号通过 SSO 注册，尚未修改初始密码。请前往个人配置页面设置自己的 Emby 本地密码。未修改前，每次打开页面都会提醒。',
                confirmText: '确认' })
            if (!isCurrent()) return
            var profileRoute = '!/settings/profile.html?userId=' + encodeURIComponent(userId)
            // The confirmation navigation must not immediately open the same reminder again.
            passwordCheckKey = token + '#' + profileRoute
            location.hash = profileRoute
        } catch (_) {
            // Dismissing a dialog does not mark the password as changed.
        } finally {
            passwordCheckPending = false
        }
    }

    function ensureProfile() {
        var anchor = Array.prototype.find.call(document.querySelectorAll('.updatePasswordForm'), function (element) {
            return element.getClientRects().length && !element.closest('.page-hidden, .hide')
        })
        if (!anchor || !window.ApiClient || !ApiClient.getCurrentUserId()) return
        // A settings view may also display another user's profile for an administrator.
        var params = new URLSearchParams((location.hash.split('?')[1] || ''))
        if (params.get('userId') && params.get('userId') !== ApiClient.getCurrentUserId()) return
        if (anchor.parentNode.querySelector('.ssoProfileForm')) return
        var form = document.createElement('form')
        form.className = 'ssoProfileForm userProfileSettingsForm padded-top fieldsets'
        form.innerHTML = '<fieldset><legend>SSO 账号绑定</legend>' +
            '<div class="fieldset-fields"><p class="legendDescription fieldset-field ssoAccount"></p>' +
            '<div class="inputContainer fieldset-field"><input is="emby-input" class="ssoPassword" ' +
            'type="password" label="Emby 本地密码" autocomplete="current-password" required maxlength="1024">' +
            '<div class="fieldDescription">验证当前账号的本地密码后管理绑定。通过 SSO 创建的账号，请先在上方设置本地密码。</div></div>' +
            '<p class="fieldset-field ssoStatus" role="status" aria-live="polite"></p></div>' +
            '<div class="fieldset-actions"><button is="emby-button" type="submit" class="raised button-submit block" disabled>' +
            '<span>加载中…</span></button></div></fieldset>'
        anchor.insertAdjacentElement('afterend', form)
        var submit = form.querySelector('button')
        var status = form.querySelector('.ssoStatus')
        var password = form.querySelector('input')
        var state
        var userId = ApiClient.getCurrentUserId()
        async function request(options) {
            if (ApiClient.getCurrentUserId() !== userId) throw new Error('登录账号已改变，请刷新页面。')
            var response = await fetch(siteBase() + '/sso/profile', Object.assign({
                credentials: 'same-origin',
                headers: { 'X-Emby-Token': ApiClient.accessToken() }
            }, options))
            if (!response.ok) {
                var html = new DOMParser().parseFromString(await response.text(), 'text/html')
                throw new Error(html.querySelector('p')?.textContent || '无法管理绑定，请确认已登录且 SSO 已启用，然后重试。')
            }
            return response.json()
        }
        async function refresh() {
            state = await request()
            form.querySelector('.ssoAccount').textContent = '当前账号：' + state.username + (state.bound ? ' · 已绑定 SSO' : ' · 未绑定 SSO')
            submit.querySelector('span').textContent = state.bound ? '解除 SSO 绑定' : '绑定 SSO 账号'
            submit.classList.toggle('button-submit', !state.bound)
            submit.classList.toggle('button-cancel', state.bound)
            submit.disabled = false
        }
        form.addEventListener('submit', async function (event) {
            event.preventDefault()
            if (!state || submit.disabled) return
            submit.disabled = true
            status.textContent = '正在验证…'
            try {
                var result = await request({ method: 'POST', body: new URLSearchParams({
                    Csrf: state.csrf, Action: state.bound ? 'unlink' : 'link', Password: password.value
                }) })
                password.value = ''
                if (result.url) {
                    location.assign(result.url)
                    return
                }
                status.textContent = '已解除 SSO 绑定，可以继续使用本地密码登录。'
            } catch (error) {
                password.value = ''
                status.textContent = error.message
            }
            try { await refresh() } catch (error) { status.textContent = error.message }
        })
        refresh().catch(function (error) { status.textContent = error.message })
    }

    function ensure() {
        ensurePasswordReminder()
        ensureProfile()
        if (!isLoginPage()) {
            if (button && button.parentNode) button.parentNode.removeChild(button)
            button = null
            return
        }
        var manual = /\/startup\/manuallogin\.html/i.test(location.hash)
        var candidates = document.querySelectorAll(manual
            ? 'form button[type="submit"].paperSubmit'
            : '.view .itemsContainer')
        var anchor = Array.prototype.find.call(candidates, function (element) {
            return element.getClientRects().length && !element.closest('.page-hidden, .hide')
        })
        if (!anchor) {
            if (button && button.parentNode) button.parentNode.removeChild(button)
            return
        }
        if (!button) {
            button = document.createElement('button')
            button.id = 'emby-sso-login'
            button.type = 'button'
            var label = document.createElement('span')
            label.textContent = 'SSO'
            button.appendChild(label)
            button.addEventListener('click', async function () {
                var currentButton = this
                if (currentButton.disabled) return
                currentButton.disabled = true
                label.textContent = '正在跳转…'
                var form
                try {
                    // Obtain the browser cookie and a one-use CSRF token without displaying the portal.
                    var response = await fetch(siteBase() + '/sso', { credentials: 'same-origin' })
                    var page = new DOMParser().parseFromString(await response.text(), 'text/html')
                    if (!response.ok) throw new Error(page.querySelector('p')?.textContent || '无法启动 SSO 登录')
                    var data = JSON.parse(page.getElementById('bootstrap').textContent)
                    if (!currentButton.isConnected || !isLoginPage()) return
                    form = document.createElement('form')
                    form.method = 'post'
                    form.action = siteBase() + '/sso/start'
                    form.hidden = true
                    for (var entry of Object.entries({ Csrf: data.csrf, Action: 'login' })) {
                        var input = document.createElement('input')
                        input.type = 'hidden'
                        input.name = entry[0]
                        input.value = entry[1]
                        form.appendChild(input)
                    }
                    document.body.appendChild(form)
                    form.submit()
                } catch (error) {
                    if (form) form.remove()
                    label.textContent = '重试 SSO 登录：' + error.message
                    currentButton.disabled = false
                }
            })
        }
        // Match Emby's theme; type=button keeps this out of the native password form submission.
        var classes = manual ? anchor.className : 'raised block paperSubmit emby-button'
        if (button.className !== classes) button.className = classes
        if (anchor.nextElementSibling !== button) anchor.insertAdjacentElement('afterend', button)
    }

    var scheduled = false
    function schedule() {
        if (scheduled) return
        scheduled = true
        setTimeout(function () { scheduled = false; ensure() }, 100)
    }

    window.addEventListener('hashchange', ensure)
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) {
            passwordCheckKey = ''
            ensurePasswordReminder()
        }
        if (event.persisted && button) {
            button.disabled = false
            button.querySelector('span').textContent = 'SSO'
        }
    })
    document.addEventListener('DOMContentLoaded', ensure)
    new MutationObserver(schedule).observe(document.documentElement, {
        childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style']
    })
    ensure()
})()

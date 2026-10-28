/* Emby 4.10.2.0 stores credentials in servercredentials3; see README "兼容性说明". */
;(async () => {
    'use strict'
    const data = JSON.parse(document.getElementById('bootstrap').textContent)
    history.replaceState(null, '', data.publicUrl + '/sso/callback')
    try {
        if (new URL(data.publicUrl).origin !== location.origin) throw new Error('登录地址与配置不一致。')
        const response = await fetch(data.publicUrl + '/sso/session', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ Ticket: data.ticket })
        })
        if (!response.ok) throw new Error('登录会话已失效或账号不允许登录，请返回重试。')
        const result = await response.json()
        const credentials = JSON.parse(localStorage.getItem('servercredentials3') || '{}')
        credentials.Servers = Array.isArray(credentials.Servers) ? credentials.Servers : []
        let server = credentials.Servers.find(item => item.Id === result.ServerId)
        if (!server) {
            server = { Id: result.ServerId }
            credentials.Servers.push(server)
        }
        server.ManualAddress = data.publicUrl
        server.ManualAddressOnly = true
        server.IsLocalServer = true
        server.UserId = result.User.Id
        server.DateLastAccessed = Date.now()
        delete server.AccessToken
        server.Users = Array.isArray(server.Users) ? server.Users.filter(user => user.UserId !== result.User.Id) : []
        server.Users.push({ UserId: result.User.Id, AccessToken: result.AccessToken })
        localStorage.setItem('servercredentials3', JSON.stringify(credentials))
        location.replace(data.publicUrl + '/web/index.html')
    } catch (error) {
        document.getElementById('status').textContent = error.message || '无法完成登录，请返回重试。'
    }
})()

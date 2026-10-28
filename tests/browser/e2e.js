#!/usr/bin/env node
'use strict'

// Browser-level check for the SSO finish path. It starts a tiny HTTPS reverse proxy in front of
// the isolated Emby instance, fetches the real dashboard, and verifies that Emby's saved
// credentials are written in the shape its ConnectionManager expects.
//
// Environment:
//   EMBY_SSO_HTTP_PORT / EMBY_SSO_HTTPS_PORT  default 18996 / 18997
//   EMBY_SSO_PUBLIC_URL                        default https://localhost:<https port>
//   EMBY_SSO_ISSUER                            default https://auth.test/auth/v1/
//   EMBY_SSO_TEST_SECRET                       required (same secret as the live harness)
//   EMBY_SSO_TLS_KEY / EMBY_SSO_TLS_CERT       optional; generated with openssl when absent
//   PLAYWRIGHT_MODULE                          optional path to the playwright package
//   PLAYWRIGHT_CHROMIUM_EXECUTABLE / EMBY_SSO_BROWSER_CHANNEL  optional browser override
//   EMBY_SSO_BROWSER_SUBJECT                   optional SSO subject; random by default

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const https = require('https')
const { execFileSync } = require('child_process')

function loadPlaywright() {
  const candidates = [
    process.env.PLAYWRIGHT_MODULE,
    path.join(__dirname, 'node_modules', 'playwright'),
    'playwright'
  ].filter(Boolean)
  let last
  for (const candidate of candidates) {
    try { return require(candidate) } catch (error) { last = error }
  }
  throw new Error('Playwright not found. Run "npm install" in tests/browser or set PLAYWRIGHT_MODULE. ' + (last ? last.message : ''))
}

const { chromium } = loadPlaywright()
const httpPort = Number(process.env.EMBY_SSO_HTTP_PORT || 18996)
const httpsPort = Number(process.env.EMBY_SSO_HTTPS_PORT || 18997)
const publicUrl = (process.env.EMBY_SSO_PUBLIC_URL || `https://localhost:${httpsPort}`).replace(/\/+$/, '')
const publicHost = new URL(publicUrl).host
const issuer = process.env.EMBY_SSO_ISSUER || 'https://auth.test/auth/v1/'
const issuerOrigin = new URL(issuer).origin
const timeout = Number(process.env.EMBY_SSO_TIMEOUT || 60000)
const secret = process.env.EMBY_SSO_TEST_SECRET
const subject = process.env.EMBY_SSO_BROWSER_SUBJECT || `browseruser${Date.now()}`
if (!/^[A-Za-z0-9_-]{1,64}$/.test(subject)) throw new Error('EMBY_SSO_BROWSER_SUBJECT must be letters, digits, underscores or hyphens')
if (!secret) throw new Error('EMBY_SSO_TEST_SECRET is required')

function tlsFiles() {
  if (process.env.EMBY_SSO_TLS_KEY && process.env.EMBY_SSO_TLS_CERT) {
    return { key: process.env.EMBY_SSO_TLS_KEY, cert: process.env.EMBY_SSO_TLS_CERT }
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'emby-sso-tls-'))
  const key = path.join(directory, 'key.pem')
  const cert = path.join(directory, 'cert.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' })
  return { key, cert }
}

function proxyServer() {
  const { key, cert } = tlsFiles()
  const server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (request, response) => {
    if (process.env.EMBY_SSO_BROWSER_DEBUG && request.url.startsWith('/sso/'))
      console.log('proxy request:', request.method, request.url, JSON.stringify({
        host: request.headers.host, origin: request.headers.origin, cookie: request.headers.cookie ? '[cookie]' : ''
      }))
    const upstream = http.request({
      host: '127.0.0.1', port: httpPort, path: request.url, method: request.method, headers: request.headers
    }, (result) => {
      response.writeHead(result.statusCode, result.headers)
      result.pipe(response)
    })
    upstream.on('error', (error) => {
      if (!response.headersSent) response.writeHead(502, { 'content-type': 'text/plain' })
      response.end(String(error))
    })
    request.pipe(upstream)
  })
  // Emby Web opens a websocket after login. Forward it so the dashboard behaves normally.
  server.on('upgrade', (request, socket, head) => {
    const upstream = http.request({
      host: '127.0.0.1', port: httpPort, path: request.url, method: request.method, headers: request.headers
    })
    upstream.on('upgrade', (result, upstreamSocket, upstreamHead) => {
      const headers = Object.entries(result.headers).map(([name, value]) => `${name}: ${value}`).join('\r\n')
      socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headers}\r\n\r\n`)
      if (upstreamHead && upstreamHead.length) socket.write(upstreamHead)
      upstreamSocket.pipe(socket)
      socket.pipe(upstreamSocket)
    })
    upstream.on('error', () => socket.destroy())
    if (head && head.length) upstream.write(head)
    upstream.end()
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(httpsPort, () => resolve(server))
  })
}

function setupHarness() {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port: httpPort, path: '/sso-test/setup', method: 'POST',
      headers: { Host: publicHost, 'X-Test-Secret': secret, 'Content-Length': 0 }
    }, (response) => {
      let body = ''
      response.on('data', (chunk) => { body += chunk })
      response.on('end', () => response.statusCode === 200
        ? resolve(body)
        : reject(new Error(`harness setup returned ${response.statusCode}: ${body}`)))
    })
    request.on('error', reject)
    request.end()
  })
}

function authenticateAdmin() {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ Username: 'sso-admin', Pw: 'SsoAdminPassword123!' })
    const request = http.request({
      host: '127.0.0.1', port: httpPort, path: '/emby/Users/AuthenticateByName', method: 'POST',
      headers: {
        Host: publicHost,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Emby-Authorization': 'MediaBrowser Client="EmbySsoTest", Device="Playwright", DeviceId="emby-sso-test", Version="1.0"'
      }
    }, (response) => {
      let data = ''
      response.on('data', (chunk) => { data += chunk })
      response.on('end', () => {
        if (response.statusCode !== 200) return reject(new Error(`admin login returned ${response.statusCode}: ${data}`))
        try {
          const result = JSON.parse(data)
          if (!result.AccessToken || !result.ServerId || !result.User?.Id)
            return reject(new Error('admin login response is missing AccessToken, ServerId or User.Id'))
          resolve(result)
        } catch (error) {
          reject(error)
        }
      })
    })
    request.on('error', reject)
    request.end(body)
  })
}

;(async () => {
  let proxy
  let browser
  try {
    if (publicUrl.startsWith('https://')) proxy = await proxyServer()
    await setupHarness()

    const launch = { headless: true, args: ['--ignore-certificate-errors'] }
    if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) launch.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
    else launch.channel = process.env.EMBY_SSO_BROWSER_CHANNEL || 'chrome'
    try {
      browser = await chromium.launch(launch)
    } catch (error) {
      if (!launch.channel) throw error
      delete launch.channel
      browser = await chromium.launch(launch)
    }

    const context = await browser.newContext({ ignoreHTTPSErrors: true })
    const page = await context.newPage()
    page.setDefaultTimeout(timeout)
    if (process.env.EMBY_SSO_BROWSER_DEBUG) {
      page.on('console', (message) => console.log('browser console:', message.type(), message.text()))
      page.on('pageerror', (error) => console.log('browser pageerror:', error.message))
      page.on('requestfailed', (request) => console.log('browser request failed:', request.url(), request.failure()?.errorText))
      page.on('response', (response) => {
        if (response.url().includes('/sso') || response.url().startsWith(issuerOrigin)
            || response.url().includes('/web/') || response.url().includes('/emby/')
            || response.url().includes('/System/'))
          console.log('browser response:', response.status(), response.url())
      })
    }

    await page.route(issuerOrigin + '/**', async (route) => {
      const authorization = new URL(route.request().url())
      const state = authorization.searchParams.get('state')
      const nonce = authorization.searchParams.get('nonce')
      if (!state || !nonce) return route.abort('failed')
      const callback = new URL(publicUrl + '/sso/callback')
      callback.searchParams.set('state', state)
      callback.searchParams.set('code', `${subject}|${nonce}`)
      await route.fulfill({ status: 302, headers: { location: callback.toString() } })
    })

    const denied = await page.goto(publicUrl + '/sso', { waitUntil: 'domcontentloaded' })
    if (denied.status() !== 401) throw new Error('Anonymous portal did not return 401')
    await page.getByRole('heading', { name: '禁止访问', exact: true }).waitFor()
    if (await page.locator('form').count()) throw new Error('Portal still has login forms')
    const sessionResponse = page.waitForResponse(
      (response) => response.url().endsWith('/sso/session') && response.request().method() === 'POST',
      { timeout })
    await page.goto(publicUrl + '/web/index.html#!/startup/manuallogin.html', { waitUntil: 'domcontentloaded' })
    await page.locator('#emby-sso-login').click()

    let response
    try {
      response = await sessionResponse
    } catch (error) {
      console.error('browser stuck at:', page.url())
      console.error('browser body:\n' + (await page.locator('body').innerText().catch(() => '')).slice(0, 1200))
      throw error
    }
    if (!response.ok()) throw new Error(`/sso/session returned ${response.status()}`)

    // The body is not read here: finish.js navigates away immediately after receiving it.
    await page.waitForURL(/\/web\/index\.html/, { timeout })
    const credentials = await page.evaluate(() => JSON.parse(localStorage.getItem('servercredentials3') || '{}'))
    const server = (credentials.Servers || []).find((item) => item.ManualAddress === publicUrl && item.UserId)
    if (!server) throw new Error('servercredentials3 does not contain the SSO server with server.UserId')
    if (!/^[0-9a-f]{32}$/i.test(server.UserId)) throw new Error('servercredentials3 UserId does not look like an Emby user id')
    const user = (server.Users || []).find((item) => item.UserId === server.UserId)
    if (!user || !user.AccessToken) throw new Error('servercredentials3 does not contain the session user token')

    if (process.env.EMBY_SSO_BROWSER_DEBUG) {
      await new Promise((resolve) => setTimeout(resolve, 4000))
      console.log('after redirect url:', page.url())
      console.log('stored credentials:', JSON.stringify({ server, user: { UserId: user.UserId, token: !!user.AccessToken } }))
      console.log('api state:', await page.evaluate(() => ({
        api: !!window.ApiClient,
        user: window.ApiClient && window.ApiClient.getCurrentUserId && window.ApiClient.getCurrentUserId(),
        server: window.ApiClient && window.ApiClient.serverId && window.ApiClient.serverId()
      })))
      console.log('dashboard body:\n' + (await page.locator('body').innerText().catch(() => '')).slice(0, 800))
    }

    try {
      await page.waitForFunction((expected) =>
        window.ApiClient && typeof window.ApiClient.getCurrentUserId === 'function'
          && window.ApiClient.getCurrentUserId() === expected,
        server.UserId, { timeout })
    } catch (error) {
      console.error('dashboard did not auto-login; url:', page.url())
      console.error('api state:', await page.evaluate(() => ({
        api: !!window.ApiClient,
        user: window.ApiClient && window.ApiClient.getCurrentUserId && window.ApiClient.getCurrentUserId(),
        server: window.ApiClient && window.ApiClient.serverId && window.ApiClient.serverId()
      })))
      console.error('dashboard body:\n' + (await page.locator('body').innerText().catch(() => '')).slice(0, 800))
      throw error
    }

    console.log(`PASS browser: /sso -> IdP -> callback -> finish -> Emby Web auto-login (${subject})`)

    const reminder = page.getByText('请修改本地密码', { exact: true })
    await reminder.waitFor({ state: 'visible' })
    await page.locator('.alertDialog.afterOpened').waitFor({ state: 'visible' })
    fs.mkdirSync(path.join(__dirname, '../../artifacts/screenshots'), { recursive: true })
    await page.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/password-reminder.png'), animations: 'disabled' })
    await page.getByRole('button', { name: '确认', exact: true }).click()
    await page.waitForURL(/settings\/profile\.html/)
    await page.locator('.updatePasswordForm').waitFor({ state: 'visible' })
    await page.reload()
    await reminder.waitFor({ state: 'visible' })
    await page.getByRole('button', { name: '确认', exact: true }).click()
    await page.locator('.txtNewPassword').fill('SsoNewLocalPassword123!')
    await page.locator('.txtNewPasswordConfirm').fill('SsoNewLocalPassword123!')
    const passwordSaved = page.waitForResponse((response) =>
        response.request().method() === 'POST' && /\/Users\/[^/]+\/Password/i.test(response.url()))
    await page.locator('.updatePasswordForm button[type="submit"]').click()
    if (!(await passwordSaved).ok()) throw new Error('native password change failed')
    const status = await page.evaluate(async () => {
        const response = await fetch('../sso/password-status', { headers: { 'X-Emby-Token': ApiClient.accessToken() } })
        return response.json()
    })
    if (status.requiresPasswordChange !== false) throw new Error('password reminder remained after saving a real password')
    const checked = page.waitForResponse((response) => response.url().includes('/sso/password-status'))
    await page.reload()
    if ((await (await checked).json()).requiresPasswordChange !== false) throw new Error('password change was not persisted')
    await page.locator('.updatePasswordForm').waitFor({ state: 'visible' })
    if (await reminder.isVisible()) throw new Error('password reminder appeared after password change')
    console.log('PASS browser: password reminder, confirmation redirect, repeat after reload, native password change clears reminder')

    await page.goto(publicUrl + '/sso', { waitUntil: 'domcontentloaded' })
    await page.waitForFunction(() => /^\d{6}$/.test(document.getElementById('login-code')?.textContent || ''))
    if (await page.locator('#username').textContent() !== subject) throw new Error('Wrong client code account')
    if (new URL(page.url()).search) throw new Error('OIDC callback parameters remain in URL')
    const clientCode = await page.locator('#login-code').textContent()
    const codeResponse = await context.request.post(publicUrl + '/Users/AuthenticateByName', {
        headers: { 'X-Emby-Authorization': 'MediaBrowser Client="BrowserCodeTest", Device="TV", DeviceId="browser-code-tv", Version="1.0"' },
        data: { Username: subject, Pw: clientCode }
    })
    if (!codeResponse.ok() || !(await codeResponse.json()).AccessToken) throw new Error('Browser code failed native login')
    fs.mkdirSync(path.join(__dirname, '../../artifacts/screenshots'), { recursive: true })
    await page.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/client-code-desktop.png'), animations: 'disabled' })
    await page.setViewportSize({ width: 375, height: 812 })
    await page.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/client-code-mobile.png'), animations: 'disabled' })
    await page.setViewportSize({ width: 1280, height: 720 })
    console.log('PASS browser: client code flow, clean callback URL, native password login')

    // The plugin injects entry.js into dashboard-ui/index.html; the login view should show the button.
    const loginContext = await browser.newContext({ ignoreHTTPSErrors: true })
    try {
      const loginPage = await loginContext.newPage()
      loginPage.setDefaultTimeout(timeout)
      await loginPage.goto(publicUrl + '/web/index.html', { waitUntil: 'domcontentloaded' })
      await loginPage.waitForFunction(() => /\/startup\/(?:login|manuallogin)\.html/i.test(location.hash), { timeout })
      const ssoButton = loginPage.locator('#emby-sso-login')
      await ssoButton.waitFor({ state: 'visible', timeout })
      const navigations = []
      loginPage.on('framenavigated', (frame) => {
        if (frame === loginPage.mainFrame()) navigations.push(new URL(frame.url()).pathname)
      })
      // Observe the navigation request: the harness IdP uses a non-resolving test domain.
      // Emby's service worker can bypass Playwright route mocks for this redirect.
      const authorizationRequest = loginPage.waitForRequest((request) =>
        request.isNavigationRequest() && new URL(request.url()).origin === issuerOrigin, { timeout })
      await ssoButton.click({ noWaitAfter: true })
      const destination = await authorizationRequest
      if (navigations.includes('/sso')) throw new Error('login button displayed the intermediate SSO portal')
      const authorization = new URL(destination.url())
      if (!authorization.searchParams.get('state') || authorization.searchParams.get('code_challenge_method') !== 'S256')
        throw new Error('direct login did not start a protected OIDC flow')
      console.log('PASS browser: one click opens IdP login without navigating to the SSO portal')
    } finally {
      await loginContext.close()
    }

    // Configuration pages must use the Emby view-controller format; the old full-page fragment
    // would load but stay page-hidden and look blank.
    const admin = await authenticateAdmin()
    const adminContext = await browser.newContext({ ignoreHTTPSErrors: true })
    try {
      await adminContext.addInitScript(({ serverId, userId, token, url }) => {
        try {
          localStorage.setItem('servercredentials3', JSON.stringify({
            Servers: [{
              Id: serverId, ManualAddress: url, ManualAddressOnly: true, IsLocalServer: true,
              UserId: userId, DateLastAccessed: Date.now(),
              Users: [{ UserId: userId, AccessToken: token }]
            }]
          }))
        } catch { }
      }, { serverId: admin.ServerId, userId: admin.User.Id, token: admin.AccessToken, url: publicUrl })
      const adminPage = await adminContext.newPage()
      adminPage.setDefaultTimeout(timeout)
      await adminPage.goto(publicUrl + '/web/index.html#!/configurationpage?name=rauthy-sso', { waitUntil: 'domcontentloaded' })
      const configPage = adminPage.locator('#rauthySsoConfig')
      try {
        await configPage.waitFor({ state: 'visible', timeout: Math.min(timeout, 30000) })
      } catch (error) {
        const classes = await configPage.getAttribute('class').catch(() => '')
        const status = await adminPage.locator('#ssoStatus').innerText().catch(() => '')
        throw new Error(`plugin configuration page is not visible (class="${classes}", status="${status}")`)
      }
      if (((await configPage.getAttribute('class')) || '').includes('page-hidden'))
        throw new Error('plugin configuration page is still page-hidden')
      try {
        await adminPage.waitForFunction(() =>
          document.querySelector('#ssoStatus') && document.querySelector('#ssoStatus').textContent === '', { timeout })
      } catch (error) {
        const message = await adminPage.locator('#ssoStatus').innerText().catch(() => '')
        throw new Error('plugin configuration page did not finish loading: ' + message)
      }
      const configuredUrl = await adminPage.locator('#ssoPublicUrl').inputValue()
      if (configuredUrl !== publicUrl) throw new Error(`configuration page PublicUrl is ${configuredUrl}, expected ${publicUrl}`)
      const callback = await adminPage.locator('#ssoCallback').innerText()
      if (!callback.includes('/sso/callback')) throw new Error('configuration page did not render the redirect URI')
      // Emby refreshes the current view on app resume. An unsaved edit must survive that refresh.
      await adminPage.locator('#ssoClientId').fill('unsaved-draft')
      await adminPage.evaluate(() => document.querySelector('#rauthySsoConfig').controller.onResume({ refresh: true }))
      await adminPage.waitForFunction(() => document.querySelector('#ssoClientId').value === 'unsaved-draft', { timeout })
      if (!(await adminPage.locator('#ssoStatus').innerText()).includes('未保存'))
        throw new Error('configuration page did not report the preserved unsaved edit')
      console.log('PASS browser: plugin configuration page renders and loads settings')
      console.log('PASS browser: unsaved settings survive an Emby view resume')
      await adminPage.reload({ waitUntil: 'domcontentloaded' })
      await adminPage.goto(publicUrl + '/web/index.html#!/settings/profile.html?userId=' + admin.User.Id, { waitUntil: 'domcontentloaded' })
      const profile = adminPage.locator('.ssoProfileForm')
      try {
        await profile.waitFor({ state: 'visible', timeout: 15000 })
      } catch (error) {
        console.error('profile URL:', adminPage.url())
        console.error('profile body:', (await adminPage.locator('body').innerText()).slice(-3000))
        throw error
      }
      await adminPage.waitForFunction(() => {
        const button = document.querySelector('.ssoProfileForm button')
        return (button && !button.disabled) || document.querySelector('.ssoStatus')?.textContent
      }, null, { timeout: 15000 })
      if (await profile.locator('button').isDisabled()) throw new Error('profile load failed: ' + await profile.innerText())
      if (await profile.locator('input:not([type="password"])').count()) throw new Error('profile asks for more than a password')
      if (!(await profile.locator('.ssoAccount').innerText()).includes('sso-admin')) throw new Error('profile did not extract current username')
      await profile.locator('input').fill('wrong-password')
      await profile.locator('button').click()
      await adminPage.waitForFunction(() => document.querySelector('.ssoStatus')?.textContent.includes('账号验证失败'))
      await profile.locator('input').fill('SsoAdminPassword123!')
      await profile.locator('button').click()
      await adminPage.waitForFunction(() => document.querySelector('.ssoAccount')?.textContent.includes('未绑定'))
      const pinPage = await adminContext.newPage()
      await pinPage.goto(publicUrl + '/sso', { waitUntil: 'domcontentloaded' })
      await pinPage.getByRole('heading', { name: '请先绑定 SSO', exact: true }).waitFor()
      if (await pinPage.locator('#code-panel').isVisible()) throw new Error('Unbound account sees PIN panel')
      if (!(await pinPage.locator('#gate-action').getAttribute('href')).includes('settings/profile.html'))
        throw new Error('Missing binding action')
      fs.mkdirSync(path.join(__dirname, '../../artifacts/screenshots'), { recursive: true })
      await pinPage.setViewportSize({ width: 1280, height: 800 })
      await pinPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/pin-unbound-desktop.png') })
      await pinPage.setViewportSize({ width: 375, height: 812 })
      await pinPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/pin-unbound-mobile.png') })
      await pinPage.goto(publicUrl + '/sso/callback?State=invalid&Code=invalid')
      await pinPage.locator('#error-message').waitFor()
      if (!(await pinPage.locator('#error-message').innerText()).trim()) throw new Error('Empty fallback message')
      await pinPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/fallback-mobile.png') })
      await pinPage.setViewportSize({ width: 1280, height: 800 })
      await pinPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/fallback-desktop.png') })
      await pinPage.close()
      console.log('PASS browser: unbound account denied with profile action; styled callback error at desktop and mobile sizes')
      await adminPage.route(issuerOrigin + '/**', async (route) => {
        const authorization = new URL(route.request().url())
        const callback = new URL(publicUrl + '/sso/callback')
        callback.searchParams.set('state', authorization.searchParams.get('state'))
        callback.searchParams.set('code', 'admin-subject|' + authorization.searchParams.get('nonce'))
        await route.fulfill({ status: 302, headers: { location: callback.toString() } })
      })
      await profile.locator('input').fill('SsoAdminPassword123!')
      await profile.locator('button').click()
      await adminPage.waitForFunction(() => document.querySelector('.ssoAccount')?.textContent.includes('已绑定'))
      fs.mkdirSync(path.join(__dirname, '../../artifacts/screenshots'), { recursive: true })
      await profile.scrollIntoViewIfNeeded()
      await adminPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/profile-desktop.png') })
      await adminPage.setViewportSize({ width: 390, height: 844 })
      await profile.scrollIntoViewIfNeeded()
      await adminPage.screenshot({ path: path.join(__dirname, '../../artifacts/screenshots/profile-mobile.png') })
      console.log('PASS browser: native profile controls, password rejection, unlink and binding return to profile')
    } finally {
      await adminContext.close()
    }
  } catch (error) {
    console.error('FAIL browser:', error.stack || error.message || error)
    process.exitCode = 1
  } finally {
    if (browser) await browser.close().catch(() => {})
    if (proxy) await new Promise((resolve) => proxy.close(resolve))
  }
})()

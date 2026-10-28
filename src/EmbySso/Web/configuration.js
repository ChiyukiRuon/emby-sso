define(['baseView', 'emby-input', 'emby-button', 'emby-checkbox', 'emby-select', 'emby-scroller'], function (BaseView) {
    'use strict';

    var pluginId = '0f20ca35-3f79-4b49-8d12-8bc5924d5ad8';
    var fields = {
        PublicUrl: 'ssoPublicUrl',
        Issuer: 'ssoIssuer',
        DiscoveryUrl: 'ssoDiscovery',
        ClientId: 'ssoClientId',
        ClientSecret: 'ssoSecret',
        ClientAuthentication: 'ssoAuth',
        Scopes: 'ssoScopes',
        RequiredClaim: 'ssoClaim',
        RequiredValue: 'ssoValue'
    };
    var checks = {
        Enabled: 'ssoEnabled',
        AllowInsecureHttp: 'ssoAllowInsecure',
        AutoCreateUsers: 'ssoAutoCreate',
        RequireVerifiedEmail: 'ssoVerifyEmail'
    };

    function withTimeout(promise, ms) {
        var timer;
        return Promise.race([
            promise,
            new Promise(function (_, reject) {
                timer = setTimeout(function () { reject(new Error('请求超时')); }, ms);
            })
        ]).finally(function () { clearTimeout(timer); });
    }

    function View(view, params) {
        BaseView.apply(this, arguments);
        this.dirty = false;
        var form = view.querySelector('form');
        form.addEventListener('submit', this.onSubmit.bind(this));
        var markDirty = function () { this.dirty = true; }.bind(this);
        form.addEventListener('input', markDirty);
        form.addEventListener('change', markDirty);
    }

    Object.assign(View.prototype, BaseView.prototype);

    View.prototype.element = function (id) {
        return this.view.querySelector('#' + id);
    };

    View.prototype.setStatus = function (text) {
        this.element('ssoStatus').textContent = text;
    };

    View.prototype.load = function () {
        var view = this.view;
        var instance = this;
        // Emby may refresh the current view when the app resumes (for example after the window
        // loses focus). Never replace unsaved edits with the last saved configuration.
        if (this.dirty) {
            this.setStatus('有未保存的修改，已保留当前填写内容。');
            return Promise.resolve();
        }
        this.setStatus('正在读取配置…');
        return withTimeout(ApiClient.getPluginConfiguration(pluginId), 15000).then(function (config) {
            if (instance.dirty) {
                instance.setStatus('有未保存的修改，已保留当前填写内容。');
                return;
            }
            Object.keys(fields).forEach(function (key) {
                instance.element(fields[key]).value = config[key] || '';
            });
            Object.keys(checks).forEach(function (key) {
                instance.element(checks[key]).checked = Boolean(config[key]);
            });
            instance.element('ssoLibraries').value = (config.NewUserLibraryIds || []).join(', ');
            instance.element('ssoCallback').textContent = 'Rauthy Redirect URI：'
                + (config.PublicUrl || '').replace(/\/$/, '') + '/sso/callback';
            instance.setStatus('');
        }, function (error) {
            console.error('Rauthy SSO configuration load failed', error);
            instance.setStatus('读取配置失败：' + (error && error.message || '未知错误')
                + '。请刷新页面；若仍失败，请检查浏览器控制台和 Emby 日志。');
        });
    };

    View.prototype.onResume = function (options) {
        BaseView.prototype.onResume.apply(this, arguments);
        return this.load();
    };

    View.prototype.onSubmit = function (event) {
        event.preventDefault();
        var view = this.view;
        var instance = this;
        var button = view.querySelector('button[type="submit"]');
        button.disabled = true;
        this.setStatus('正在保存…');
        withTimeout(ApiClient.getPluginConfiguration(pluginId), 15000).then(function (config) {
            Object.keys(fields).forEach(function (key) {
                config[key] = instance.element(fields[key]).value.trim();
            });
            Object.keys(checks).forEach(function (key) {
                config[key] = instance.element(checks[key]).checked;
            });
            config.NewUserLibraryIds = instance.element('ssoLibraries').value.split(',')
                .map(function (value) { return value.trim(); }).filter(Boolean);
            return withTimeout(ApiClient.updatePluginConfiguration(pluginId, config), 15000);
        }).then(function (result) {
            instance.dirty = false;
            Dashboard.processPluginConfigurationUpdateResult(result);
            instance.setStatus('已保存。');
        }, function (error) {
            console.error('Rauthy SSO configuration save failed', error);
            instance.setStatus('保存失败：' + (error && error.message || '未知错误') + '。请检查配置后重试。');
        }).then(function () {
            button.disabled = false;
        });
    };

    return View;
});

#!/usr/bin/env python3
"""Build, start, test and stop an isolated Emby instance for the SSO plugin.

The script never touches a production Emby data directory. It creates a disposable programdata
directory, installs the release plugin plus the TEST-ONLY live harness, runs the HTTP integration
test, and (by default) runs the browser end-to-end test against a local HTTPS proxy.
"""
import argparse
import os
import pathlib
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / '.cache' / 'emby-4.10.2.0.7z'
DEFAULT_EMBY = ROOT / '.cache' / 'emby' / 'system'
DEFAULT_DATA = ROOT / '.cache' / 'live-test-data'


def log(message):
    print(f'[live-test] {message}', flush=True)


def die(message):
    raise SystemExit(f'[live-test] {message}')


def port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex(('127.0.0.1', port)) == 0


def ensure_emby(system):
    exe = system / 'EmbyServer.exe'
    dll = system / 'EmbyServer.dll'
    if exe.exists() and dll.exists():
        return exe
    if ARCHIVE.exists():
        seven_zip = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
        if not seven_zip:
            for candidate in (r'C:\Program Files\7-Zip\7z.exe', r'C:\Program Files (x86)\7-Zip\7z.exe'):
                if pathlib.Path(candidate).exists():
                    seven_zip = candidate
                    break
        if seven_zip:
            log(f'extracting {ARCHIVE.name} into {system.parent}')
            subprocess.run([seven_zip, 'x', str(ARCHIVE), f'-o{system.parent}', '-y'], check=True)
            if exe.exists() and dll.exists():
                return exe
    die('Emby 4.10.2.0 server not found. Extract .cache/emby-4.10.2.0.7z under .cache/emby '
        'or pass --emby <path to the Emby system directory>.')


def write_config(data, http_port, https_port):
    config = data / 'config'
    config.mkdir(parents=True, exist_ok=True)
    (config / 'system.xml').write_text(f'''<?xml version="1.0"?>
<ServerConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <EnableDebugLevelLogging>false</EnableDebugLevelLogging>
  <EnableAutoUpdate>false</EnableAutoUpdate>
  <LogFileRetentionDays>3</LogFileRetentionDays>
  <RunAtStartup>false</RunAtStartup>
  <IsStartupWizardCompleted>true</IsStartupWizardCompleted>
  <EnableUPnP>false</EnableUPnP>
  <PublicPort>{http_port}</PublicPort>
  <PublicHttpsPort>{https_port}</PublicHttpsPort>
  <HttpServerPortNumber>{http_port}</HttpServerPortNumber>
  <HttpsPortNumber>{https_port}</HttpsPortNumber>
  <EnableHttps>false</EnableHttps>
  <IsPortAuthorized>true</IsPortAuthorized>
  <AutoRunWebApp>false</AutoRunWebApp>
  <EnableRemoteAccess>true</EnableRemoteAccess>
  <ValidateImageTags>false</ValidateImageTags>
  <UICulture>en-us</UICulture>
  <RequireHttps>false</RequireHttps>
  <IsBehindProxy>false</IsBehindProxy>
  <EnableCaseSensitiveItemIds>true</EnableCaseSensitiveItemIds>
  <DatabaseCacheSizeMB>128</DatabaseCacheSizeMB>
</ServerConfiguration>
''', encoding='utf-8')


def build():
    env = os.environ.copy()
    env['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
    env['DOTNET_NOLOGO'] = '1'
    log('building plugin (Release)')
    subprocess.run(['dotnet', 'build', str(ROOT / 'src' / 'EmbySso' / 'EmbySso.csproj'),
                    '-c', 'Release'], cwd=ROOT, env=env, check=True)
    log('building live harness (Release)')
    subprocess.run(['dotnet', 'build', str(ROOT / 'tests' / 'EmbySso.LiveHarness' / 'EmbySso.LiveHarness.csproj'),
                    '-c', 'Release'], cwd=ROOT, env=env, check=True)


def install_plugins(data):
    plugins = data / 'plugins'
    plugins.mkdir(parents=True, exist_ok=True)
    plugin = ROOT / 'artifacts' / 'EmbySso.dll'
    harness = ROOT / 'tests' / 'EmbySso.LiveHarness' / 'bin' / 'Release' / 'net8.0' / 'EmbySso.LiveHarness.dll'
    if not plugin.exists():
        die(f'missing {plugin}; build the plugin first')
    if not harness.exists():
        die(f'missing {harness}; build the live harness first')
    shutil.copy2(plugin, plugins / plugin.name)
    shutil.copy2(harness, plugins / harness.name)


def start_server(exe, data, env, log_path):
    log(f'starting Emby with data directory {data}')
    stream = open(log_path, 'w', encoding='utf-8')
    kwargs = {}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    process = subprocess.Popen([str(exe), '-programdata', str(data), '-nointerface', '-nobrowser'],
                               cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, **kwargs)
    return process, stream


def stop_server(process):
    if process is None or process.poll() is not None:
        return
    log('stopping Emby')
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except Exception:
        pass
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()


def wait_ready(process, port, log_path, timeout=90):
    url = f'http://127.0.0.1:{port}/System/Info/Public'
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            print_log(log_path)
            die(f'Emby exited with code {process.returncode}')
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    log('Emby is ready')
                    return
        except Exception:
            pass
        time.sleep(0.5)
    print_log(log_path)
    die('timed out waiting for Emby to start')


def print_log(path, lines=60):
    if not path.exists():
        return
    try:
        content = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return
    print('\n'.join(content[-lines:]))


def make_certificate(directory):
    key = directory / 'key.pem'
    cert = directory / 'cert.pem'
    directory.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                             '-keyout', str(key), '-out', str(cert), '-days', '1',
                             '-subj', '/CN=localhost',
                             '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        # MSYS/Git Bash may rewrite a leading /CN=... as a path. Retry with the escaped form.
        result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                 '-keyout', str(key), '-out', str(cert), '-days', '1',
                                 '-subj', '//CN=localhost',
                                 '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        die('unable to generate a test TLS certificate with openssl: ' + result.stderr.strip())
    return key, cert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emby', type=pathlib.Path, default=DEFAULT_EMBY,
                        help='Emby system directory (default: .cache/emby/system)')
    parser.add_argument('--data', type=pathlib.Path, default=DEFAULT_DATA,
                        help='disposable Emby programdata directory (default: .cache/live-test-data)')
    parser.add_argument('--http-port', type=int, default=18996, help='Emby HTTP port (default: 18996)')
    parser.add_argument('--https-port', type=int, default=18997, help='test HTTPS proxy port (default: 18997)')
    parser.add_argument('--no-build', action='store_true', help='reuse the current Release artifacts')
    parser.add_argument('--no-browser', action='store_true', help='skip the browser end-to-end test')
    parser.add_argument('--insecure-http', action='store_true',
                        help='test an http:// PublicUrl with AllowInsecureHttp (test only; no TLS proxy)')
    parser.add_argument('--keep', action='store_true', help='keep the programdata directory and logs after the run')
    parser.add_argument('--playwright-module', default=None,
                        help='path to the playwright package (or set PLAYWRIGHT_MODULE)')
    args = parser.parse_args()

    if port_open(args.http_port):
        die(f'port {args.http_port} is already in use; stop the other Emby instance first')
    if not args.insecure_http and not args.no_browser and port_open(args.https_port):
        die(f'port {args.https_port} is already in use; stop the other HTTPS listener first')

    exe = ensure_emby(args.emby)
    if args.data.resolve() == ROOT.resolve():
        die('--data must not be the repository root')
    if args.data.exists():
        log(f'cleaning {args.data}')
        shutil.rmtree(args.data)
    args.data.mkdir(parents=True, exist_ok=True)
    write_config(args.data, args.http_port, args.https_port)

    if not args.no_build:
        try:
            build()
        except subprocess.CalledProcessError as error:
            die(f'build failed with exit code {error.returncode}')
    install_plugins(args.data)

    secret = secrets.token_urlsafe(32)
    public_url = (f'http://localhost:{args.http_port}' if args.insecure_http
                  else f'https://localhost:{args.https_port}')
    env = os.environ.copy()
    env.update({
        'EMBY_SSO_TEST_SECRET': secret,
        'EMBY_SSO_BASE': f'http://127.0.0.1:{args.http_port}',
        'EMBY_SSO_PUBLIC_URL': public_url,
        'EMBY_SSO_HTTP_PORT': str(args.http_port),
        'EMBY_SSO_HTTPS_PORT': str(args.https_port),
        'EMBY_SSO_ALLOW_INSECURE_HTTP': '1' if args.insecure_http else '',
        'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
        'DOTNET_NOLOGO': '1',
    })
    if args.playwright_module:
        env['PLAYWRIGHT_MODULE'] = args.playwright_module

    log_path = args.data / 'server.log'
    process = None
    stream = None
    try:
        process, stream = start_server(exe, args.data, env, log_path)
        wait_ready(process, args.http_port, log_path)

        log('running HTTP integration test')
        subprocess.run([sys.executable, str(ROOT / 'tests' / 'live-http.py')], cwd=ROOT, env=env, check=True)

        if not args.no_browser:
            if not args.insecure_http:
                key, cert = make_certificate(args.data / 'tls')
                env['EMBY_SSO_TLS_KEY'] = str(key)
                env['EMBY_SSO_TLS_CERT'] = str(cert)
            log('running browser end-to-end test' + (' over HTTP (insecure)' if args.insecure_http else ''))
            subprocess.run(['node', str(ROOT / 'tests' / 'browser' / 'e2e.js')], cwd=ROOT, env=env, check=True)
    except subprocess.CalledProcessError as error:
        print_log(log_path)
        die(f'test failed with exit code {error.returncode}')
    finally:
        stop_server(process)
        if stream:
            stream.close()
        if not args.keep:
            shutil.rmtree(args.data, ignore_errors=True)
        else:
            log(f'kept {args.data}')

    log('PASS all live tests')


if __name__ == '__main__':
    main()

"""Fetch pinned NuGet packages into a local feed when Windows TLS is unavailable."""
import argparse
import io
import pathlib
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

DEFAULT_PACKAGES = [
    'MediaBrowser.Server.Core@4.10.0.24-beta2',
    'Microsoft.IdentityModel.JsonWebTokens@8.14.0',
    'ILRepack.Lib.MSBuild.Task@2.0.48',
]

parser = argparse.ArgumentParser()
parser.add_argument('--proxy', default=None)
parser.add_argument('packages', nargs='*', help='PackageId@Version (default: the pinned build dependencies)')
args = parser.parse_args()
opener = urllib.request.build_opener(urllib.request.ProxyHandler(
    {'https': args.proxy} if args.proxy else {}))
feed = pathlib.Path(__file__).resolve().parents[1] / '.cache' / 'feed'
feed.mkdir(parents=True, exist_ok=True)
seen = set()

def fetch(name, version):
    name, version = name.lower(), version.lower()
    if (name, version) in seen:
        return
    seen.add((name, version))
    target = feed / f'{name}.{version}.nupkg'
    if not target.exists():
        url = f'https://api.nuget.org/v3-flatcontainer/{name}/{version}/{name}.{version}.nupkg'
        target.write_bytes(opener.open(url, timeout=45).read())
    print(f'{name}@{version}', flush=True)
    with zipfile.ZipFile(io.BytesIO(target.read_bytes())) as archive:
        manifest = next(n for n in archive.namelist() if n.endswith('.nuspec'))
        root = ET.fromstring(archive.read(manifest))
    ns = {'n': root.tag.split('}')[0][1:]}
    dependencies = root.find('n:metadata/n:dependencies', ns)
    if dependencies is None:
        return
    groups = dependencies.findall('n:group', ns)
    candidates = ['net8.0', 'net6.0', '.NETStandard2.1', '.NETStandard2.0', 'netstandard2.0', '']
    selected = None
    for framework in candidates:
        selected = next((g for g in groups if g.get('targetFramework', '') == framework), None)
        if selected is not None:
            break
    items = selected.findall('n:dependency', ns) if selected is not None else dependencies.findall('n:dependency', ns)
    for dep in items:
        minimum = dep.attrib['version'].strip('[]()').split(',')[0].strip()
        if not minimum:
            raise ValueError(f'No minimum version: {dep.attrib}')
        fetch(dep.attrib['id'], minimum)

for package in args.packages or DEFAULT_PACKAGES:
    fetch(*package.split('@', 1))

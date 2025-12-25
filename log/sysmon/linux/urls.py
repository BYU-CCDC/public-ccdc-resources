# Terrible script for scraping Sysmon package download links, but it mostly works
import requests
from bs4 import BeautifulSoup
import re
import json

def get_hrefs(text):
    soup = BeautifulSoup(text, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True)]

def find_best(packages):
    best = [0, 0, 0]
    for package in packages:
        if version := re.search(r'(\d\.\d\.\d(-\d)?)', package):
            version = version.group(1).split('.')
            version = [int(part) for item in version for part in item.split('-')]
            for i, num in enumerate(version):
                if num > best[i]:
                    best = version[:]
                    break
                elif num < best[i]:
                    break
    ret = '.'.join([str(part) for part in best[:3]])
    try:
        ret += '-' + str(best[3])
    except IndexError:
        pass
    return ret

downloads = {}
distros = ['debian', 'ubuntu', 'centos', 'redhat', 'opensuse', 'sles', 'fedora', 'rhel']
url = 'https://packages.microsoft.com/'
r = requests.get(url)
hrefs = get_hrefs(r.text)

for distro in hrefs:
    versions_url = url + distro
    if distro.rstrip('/') not in distros:
        continue
    r = requests.get(versions_url)
    versions = get_hrefs(r.text)
    for version in versions:
        try:
            print(f'{distro.rstrip("/").title()} {version.rstrip("/")}')
            r = requests.get(versions_url + version)
            paths = get_hrefs(r.text)
            if 'prod/' in paths:
                r = requests.get(versions_url + version + 'prod/')
                sources = get_hrefs(r.text)
                if 'pool/' in sources:
                    packages_url = versions_url + version + 'prod/pool/main/'
                    r = requests.get(packages_url)
                elif 'Packages/' in sources:
                    packages_url = versions_url + version + 'prod/Packages/'
                    r = requests.get(packages_url)
                packages = get_hrefs(r.text)
                if 's/' in packages:
                    s_packages_url = packages_url + 's/'
                    r = requests.get(s_packages_url)
                    s_packages = get_hrefs(r.text)
                    if 'sysinternalsebpf/' in s_packages or 'sysmonforlinux/' in s_packages:
                        extra_path = True
                        r = requests.get(s_packages_url + 'sysinternalsebpf/')
                        sysinternals_packages = get_hrefs(r.text)
                        sysinternals_packages = [package for package in sysinternals_packages if package.startswith('sysinternalsebpf')]
                        r = requests.get(s_packages_url + 'sysmonforlinux/')
                        sysmon_packages = get_hrefs(r.text)
                        sysmon_packages = [package for package in sysmon_packages if package.startswith('sysmonforlinux')]
                    else:
                        extra_path = False
                        sysinternals_packages = [package for package in s_packages if package.startswith('sysinternalsebpf')]
                        sysmon_packages = [package for package in s_packages if package.startswith('sysmonforlinux')]
                    if len(sysinternals_packages):
                        best = find_best(sysinternals_packages)
                        name = [package for package in sysinternals_packages if best in package][0]
                        downloads[f"{distro.rstrip('/')}-{version.rstrip('/')}"] = {}
                        if extra_path:
                            downloads[f"{distro.rstrip('/')}-{version.rstrip('/')}"]['sysinternals'] = s_packages_url + 'sysinternalsebpf/' + name
                        else:
                            downloads[f"{distro.rstrip('/')}-{version.rstrip('/')}"]['sysinternals'] = s_packages_url + name
                    if len(sysmon_packages):
                        best = find_best(sysmon_packages)
                        name = [package for package in sysmon_packages if best in package][0]
                        if extra_path:
                            downloads[f"{distro.rstrip('/')}-{version.rstrip('/')}"]['sysmon'] = s_packages_url + 'sysmonforlinux/' + name
                        else:
                            downloads[f"{distro.rstrip('/')}-{version.rstrip('/')}"]['sysmon'] = s_packages_url + name
        except Exception as e:
            print(f"Error fetching data for {distro}{version}: {e}")
            continue
print()
# print(downloads)
# with open("links.json", "w") as file:
#     json.dump(downloads, file, indent=4)

for candidate in downloads:
    if 'sysmon' in downloads[candidate] and 'sysinternals' in downloads[candidate]:
        var_name = candidate.replace('-', '_').replace('.', '_')
        print(f'{var_name + "_sysmon"}="{downloads[candidate]["sysmon"]}"')
        print(f'{var_name + "_sysinternals"}="{downloads[candidate]["sysinternals"]}"')
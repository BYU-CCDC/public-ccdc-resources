# Helper script to scrape indexer and forwarder download URLs from the Splunk website

import requests
from bs4 import BeautifulSoup
import re
import sys

indexer_url = 'https://www.splunk.com/en_us/download/splunk-enterprise.html'
uf_url = 'https://www.splunk.com/en_us/download/universal-forwarder.html'

def fetch_links(url):
    links = set()
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        a_tags = soup.find_all('a', attrs={'data-wget': True})
        for tag in a_tags:
            match = re.search(r'wget -O splunk(?:forwarder)?-((?:\d\.){2}\d)-[^-\.\s]+[-\.](\S+) "(https://\S+)"', tag['data-wget'])
            version = match.group(1)
            name = match.group(2)
            url = match.group(3)
            links.add((version, name, url))
        return links
    else:
        print(f"Failed to retrieve content from {url}. Status code: {response.status_code}")
        sys.exit(1)

def format_template(template, item, indexer=False):
    version = item[0]
    name = item[1]
    url = item[2]
    if name.endswith('x64-release.msi'):
        # Windows 64-bit
        if indexer:
            return template.replace('$INDEXER_WINDOWS_X64', url)
        return template.replace('$WINDOWS_X64', url)
    elif name.endswith('x86-release.msi'):
        # Windows 32-bit
        return template.replace('$WINDOWS_X86', url)
    elif name.endswith('Linux-x86_64.tgz'):
        # Linux x64 tgz
        if indexer:
            return template.replace('$INDEXER_TGZ', url)
        return template.replace('$TGZ', url)
    elif name.endswith('amd64.deb'):
        # Linux x64 deb
        if indexer:
            return template.replace('$INDEXER_DEB', url)
        return template.replace('$DEB', url)
    elif name.endswith('x86_64.rpm'):
        # Linux x64 rpm
        if indexer:
            return template.replace('$INDEXER_RPM', url)
        return template.replace('$RPM', url)
    elif name.endswith('s390x.rpm'):
        # S390X RPM
        return template.replace('$S390X_RPM', url)
    elif name.endswith('s390x.tgz'):
        # S390X TGZ
        return template.replace('$S390X_TGZ', url)
    elif name.endswith('aarch64.rpm'):
        # ARM RPM
        return template.replace('$ARM_RPM', url)
    elif name.endswith('armv8.deb'):
        # ARM DEB
        return template.replace('$ARM_DEB', url)
    elif name.endswith('armv8.tgz'):
        # ARM TGZ
        return template.replace('$ARM_TGZ', url)
    elif name.endswith('ppc64le.tgz'):
        # PPCLE TGZ
        return template.replace('$PPCLE_TGZ', url)
    elif name.endswith('ppc64le.rpm'):
        # PPCLE RPM
        return template.replace('$PPCLE_RPM', url)
    elif name.endswith('darwin-intel.dmg'):
        # Mac Intel DMG
        if indexer:
            return template.replace('$INDEXER_MAC_INTEL_DMG', url)
        return template.replace('$MAC_INTEL_DMG', url)
    elif name.endswith('darwin-intel.tgz'):
        # Mac Intel TGZ
        if indexer:
            return template.replace('$INDEXER_MAC_INTEL_TGZ', url)
        return template.replace('$MAC_INTEL_TGZ', url)
    elif name.endswith('darwin-universal2.dmg'):
        # Mac Universal DMG
        return template.replace('$MAC_UNIV_DMG', url)
    elif name.endswith('darwin-universal2.tgz'):
        # Mac Universal TGZ
        return template.replace('$MAC_UNIV_TGZ', url)
    elif name.endswith('freebsd12-amd64.tgz'):
        # FreeBSD 12 TGZ
        return template.replace('$FREEBSD12_TGZ', url)
    elif name.endswith('freebsd12-amd64.txz'):
        # FreeBSD 12 TXZ
        return template.replace('$FREEBSD12_TXZ', url)
    elif name.endswith('freebsd13-amd64.tgz'):
        # FreeBSD 13 TGZ
        return template.replace('$FREEBSD13_TGZ', url)
    elif name.endswith('freebsd13-amd64.txz'):
        # FreeBSD 13 TXZ
        return template.replace('$FREEBSD13_TXZ', url)
    elif name.endswith('solaris-sparc.p5p'):
        # Solaris Sparc P5P
        return template.replace('$SOLARIS_SPARC_P5P', url)
    elif name.endswith('SunOS-sparc.tar.Z'):
        # Solaris Sparc Z
        return template.replace('$SOLARIS_SPARC_Z', url)
    elif name.endswith('solaris-intel.p5p'):
        # Solaris Intel P5P
        return template.replace('$SOLARIS_INTEL_P5P', url)
    elif name.endswith('SunOS-x86_64.tar.Z'):
        # Solaris Intel TAR.Z
        return template.replace('$SOLARIS_INTEL_TARZ', url)
    elif name.endswith('AIX-powerpc.tgz'):
        # AIX PPC TGZ
        return template.replace('$AIX_PPC_TGZ', url)
    else:
        print('ERROR: Unknown filename:', name)
        return template

markdown_template = '''\
# Splunk Download URLs
## Indexer
Windows x64 (64 bit) msi: [$INDEXER_WINDOWS_X64]($INDEXER_WINDOWS_X64)<br>
Linux .tgz: [$INDEXER_TGZ]($INDEXER_TGZ)<br>
Linux .deb: [$INDEXER_DEB]($INDEXER_DEB)<br>
Linux .rpm: [$INDEXER_RPM]($INDEXER_RPM)<br>
Mac Intel .dmg: [$INDEXER_MAC_INTEL_DMG]($INDEXER_MAC_INTEL_DMG)<br>
Mac Intel .tgz: [$INDEXER_MAC_INTEL_TGZ]($INDEXER_MAC_INTEL_TGZ)<br>

## Forwarder
Windows x64 (64 bit) msi: [$WINDOWS_X64]($WINDOWS_X64)<br>
Windows x86 (32 bit) msi: [$WINDOWS_X86]($WINDOWS_X86)<br>
Linux .tgz: [$TGZ]($TGZ)<br>
Linux .deb: [$DEB]($DEB)<br>
Linux .rpm: [$RPM]($RPM)<br>
S390X .rpm: [$S390X_RPM]($S390X_RPM)<br>
S390X .tgz: [$S390X_TGZ]($S390X_TGZ)<br>
ARM .rpm: [$ARM_RPM]($ARM_RPM)<br>
ARM .deb: [$ARM_DEB]($ARM_DEB)<br>
ARM .tgz: [$ARM_TGZ]($ARM_TGZ)<br>
PPCLE .tgz: [$PPCLE_TGZ]($PPCLE_TGZ)<br>
PPCLE .rpm: [$PPCLE_RPM]($PPCLE_RPM)<br>
Mac Intel .dmg: [$MAC_INTEL_DMG]($MAC_INTEL_DMG)<br>
Mac Intel .tgz: [$MAC_INTEL_TGZ]($MAC_INTEL_TGZ)<br>
Mac Universal .dmg: [$MAC_UNIV_DMG]($MAC_UNIV_DMG)<br>
Mac Universal .tgz: [$MAC_UNIV_TGZ]($MAC_UNIV_TGZ)<br>
FreeBSD12 .tgz: [$FREEBSD12_TGZ]($FREEBSD12_TGZ)<br>
FreeBSD12 .txz: [$FREEBSD12_TXZ]($FREEBSD12_TXZ)<br>
FreeBSD13 .tgz: [$FREEBSD13_TGZ]($FREEBSD13_TGZ)<br>
FreeBSD13 .txz: [$FREEBSD13_TXZ]($FREEBSD13_TXZ)<br>
Solaris Sparc .p5p: [$SOLARIS_SPARC_P5P]($SOLARIS_SPARC_P5P)<br>
Solaris Sparc .z: [$SOLARIS_SPARC_Z]($SOLARIS_SPARC_Z)<br>
Solaris Intel .p5p: [$SOLARIS_INTEL_P5P]($SOLARIS_INTEL_P5P)<br>
Solaris Intel .tar.z: [$SOLARIS_INTEL_TARZ]($SOLARIS_INTEL_TARZ)<br>
AIX PPC .tgz: [$AIX_PPC_TGZ]($AIX_PPC_TGZ)<br>
'''

bash_template = '''\
# Indexer
deb="$INDEXER_DEB"
rpm="$INDEXER_RPM"
tgz="$INDEXER_TGZ"

# Forwarder
deb="$DEB"
rpm="$RPM"
tgz="$TGZ"
arm_deb="$ARM_DEB"
arm_rpm="$ARM_RPM"
arm_tgz="$ARM_TGZ"
'''

if __name__ == '__main__':
    print('Fetching Indexer URLs...')
    for item in fetch_links(indexer_url):
        bash_template = format_template(bash_template, item, True)
        markdown_template = format_template(markdown_template, item, True)

    print('Fetching Universal Forwarder URLs...')
    for item in fetch_links(uf_url):
        bash_template = format_template(bash_template, item, False)
        markdown_template = format_template(markdown_template, item, False)
    
    print()
    print('Markdown:')
    print(markdown_template)
    print('Bash:')
    print(bash_template)
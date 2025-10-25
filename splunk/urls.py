import requests
from bs4 import BeautifulSoup
import sys

versions = ['9.2.10']
oses = ['windows', 'linux', 'solaris', 'osx', 'freebsd', 'aix']

class SplunkDownload:
    def __init__(self, extension, filename, url):
        self.extension = extension
        self.filename = filename
        self.url = url

    def __str__(self):
        return f"{self.extension} - [{self.filename}]({self.url})"

class SplunkVersion:
    def __init__(self, version, bits, os):
        self.version = version
        self.bits = bits
        self.os = os
        self.downloads = []
    
    def __str__(self):
        download_str = "\n- ".join(str(download) for download in self.downloads)
        return f"{self.os} ({self.bits})\n- {download_str}\n"

    def add_download(self, extension, filename, url):
        self.downloads.append(SplunkDownload(extension, filename, url))

def scrape(scrape_version, type):
    results = []
    if scrape_version == 'latest':
        indexer_url = 'https://www.splunk.com/en_us/download/splunk-enterprise.html'
        uf_url = 'https://www.splunk.com/en_us/download/universal-forwarder.html'
    else:
        indexer_url = 'https://www.splunk.com/en_us/download/previous-releases.html'
        uf_url = 'https://www.splunk.com/en_us/download/previous-releases-universal-forwarder.html'
    
    if type == 'indexer':
        # Fetch Indexer HTML content
        if r:=requests.get(indexer_url):
            if r.status_code == 200:
                html = r.text
            else:
                print(f"Failed to retrieve content from {indexer_url}. Status code: {r.status_code}")
                sys.exit(1)
    elif type == 'uf':
        # Fetch UF HTML content
        if r:=requests.get(uf_url):
            if r.status_code == 200:
                html = r.text
            else:
                print(f"Failed to retrieve content from {uf_url}. Status code: {r.status_code}")
                sys.exit(1)
    else:
        print("ERROR: type must be 'indexer' or 'uf'")
        sys.exit(1)

    # For each OS we want to scrape
    for os in oses:
        soup = BeautifulSoup(html, 'html.parser')
        os_div = soup.find('div', id=os)
        if not os_div:
            continue
        # Get each version listing for each OS
        for version_block in os_div.find_all("div", class_="row version-block"):
            # Extract column data
            divs = version_block.find_all("div")
            if len(divs) < 4:
                print("ERROR: insufficient data in version block")
                continue
            version = divs[0].text.strip()
            bits = divs[1].text.strip()
            os = divs[2].text.strip()
            downloads = divs[3]
            # We only want the version we're scraping for
            if version != scrape_version:
                continue
            splunk_version = SplunkVersion(version, bits, os)

            # Extract download links
            for row in downloads.find_all("div", class_="versions-table"):
                extension = row.find("div", class_="filename").text.strip()
                button = row.find("div", class_="download-btn")
                if not extension or not button:
                    print("ERROR: could not find extension and/or download button")
                    continue
                filename = button.find("a")['data-filename']
                url = button.find("a")['data-link']
                splunk_version.add_download(extension, filename, url)
            
            results.append(splunk_version)
    return results

for version in versions:
    indexer_results = scrape(version, 'indexer')
    uf_results = scrape(version, 'uf')

    indexer_markdown = "\n".join(str(result) for result in indexer_results)
    uf_markdown = "\n".join(str(result) for result in uf_results)

    markdown = f"""# Splunk Download URLs
Version: [{version}](https://docs.splunk.com/Documentation/Splunk/{version}/Installation/Systemrequirements)

## Indexer
{indexer_markdown}
## Universal Forwarder
{uf_markdown}"""

    if input("Write to README.md? (y/n): ").lower() == 'y':
        with open(f'README.md', 'w') as f:
            f.write(markdown)
        print("Wrote to README.md")
    
    if input("Output bash variables? (y/n): ").lower() == 'y':
        linux_indexer = next(res for res in indexer_results if 'linux' in res.os.lower() and res.bits == '64-bit')
        linux_uf_64 = next(res for res in uf_results if 'linux' in res.os.lower() and res.bits == '64-bit')
        linux_uf_arm = next(res for res in uf_results if 'linux' in res.os.lower() and res.bits == 'ARM')
        bash_vars = f"""# Indexer
indexer_deb="{next(d.url for d in linux_indexer.downloads if d.extension.endswith('deb'))}"
indexer_rpm="{next(d.url for d in linux_indexer.downloads if d.extension.endswith('rpm'))}"
indexer_tgz="{next(d.url for d in linux_indexer.downloads if d.extension.endswith('tgz'))}"

# Forwarder
deb="{next(d.url for d in linux_uf_64.downloads if d.extension.endswith('deb'))}"
rpm="{next(d.url for d in linux_uf_64.downloads if d.extension.endswith('rpm'))}"
tgz="{next(d.url for d in linux_uf_64.downloads if d.extension.endswith('tgz'))}"
arm_deb="{next(d.url for d in linux_uf_arm.downloads if d.extension.endswith('deb'))}"
arm_rpm="{next(d.url for d in linux_uf_arm.downloads if d.extension.endswith('rpm'))}"
arm_tgz="{next(d.url for d in linux_uf_arm.downloads if d.extension.endswith('tgz'))}"
"""
        print(bash_vars)
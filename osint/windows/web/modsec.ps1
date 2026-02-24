[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"


iwr "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v2.9.7/ModSecurityIIS_2.9.7-64b-64.msi" -o "C:\Users\Administrator\Documents\iid_modsec.msi" -UseBasicParsing
iwr "https://github.com/coreruleset/coreruleset/releases/download/v4.12.0/coreruleset-4.12.0-minimal.zip" -o "C:\Users\Administrator\Documents\ruleset.zip" -UseBasicParsing
iwr "https://go.microsoft.com/fwlink/?LinkID=615136" -o "C:\Users\Administrator\Documents\ARR.msi" -UseBasicParsing
iwr "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi" -o "C:\Users\Administrator\Documents\Rewrite.msi" -UseBasicParsing

netsh a f del r n=WEB_OUT
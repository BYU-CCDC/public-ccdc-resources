# Domain hardening GPO catalog

This describes the policies imported from the current draft package and the run-specific changes applied after import. “Enforced” means the link is marked enforced; links marked otherwise can be affected by normal OU inheritance and precedence. Computer-filtered links grant Apply Group Policy only to the listed computer accounts; broad principals retain read access. Review the source backups and test policy interactions before changing production links.

## Draft package source and handling

`Invoke-DomainHardening` imports linked GPOs from the `gpo-v1` draft package. By default it downloads and expands `GPO-Core.zip` from `https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/GPO-Core.zip`. This archive contains 16 baseline and standard role policies. When an additional profile or named firewall-port exception is selected, it downloads and validates `GPO-Additional.zip` from the same public folder; that archive contains eight optional policies. The optional backups use their own extraction root and manifest, preserving the core package for later imports. The canonical archives and generator remain in the adjacent project directory: `gpo-v1/CCDC-GPO-v1-core.zip`, `gpo-v1/CCDC-GPO-v1-additional.zip`, and `gpo-v1/Build-Split-GpoPackages.ps1`. Explicit `-GpoDraftUri` and `-GpoDraftPath` inputs still accept a full package ZIP or expanded package folder. The legacy `gpos.zip` archive is not used by the domain orchestrator.

The runner validates the core package before starting GPO work. If an optional GPO or custom port exception is selected, it validates the additional package before linking any GPOs. If either required package cannot be fetched or validated, it skips GPO linking and reports the failure; independent non-GPO hardening steps continue. It never falls back to legacy backups or PowerShell-authored GPOs. Run-specific values may be applied through PowerShell only after importing the corresponding draft backup.

## Importable draft policies

The current draft manifest lists all 24 required Windows-exported backup policies. The new Audit policy carries the legacy audit settings and advanced-audit subcategories; Common has no audit values. The runner must import these backups before linking and may then apply run-specific edits. Exact static policy contents are documented in `gpo-v1/README.md` and the individual GPO reports.

| Draft policy | Intended use | Runtime edits / scope |
|---|---|---|
| `CCDC v1 Domain Common Baseline` | Common domain baseline | Static FIPS, password-age, and privilege-right settings are in the backup; linked to the domain root. |
| `CCDC v1 Domain Controller Baseline` | DC firewall and LDAP baseline | Static LDAP, Kerberos, and replication settings are in the backup; linked to DC-containing OUs and filtered to Domain Controllers. |
| `CCDC v1 Domain Firewall Baseline` | Domain firewall defaults and core rules | Static NTP and management rules are in the backup; broad web egress cleanup remains a runtime compatibility step. Local rule merging is disabled, so exceptions must also be GPO-backed. |
| `CCDC v1 Defender Baseline` | Defender settings | Linked according to the draft baseline design. |
| `CCDC v1 GPO Update Interval` | Background policy refresh interval | Linked according to the draft baseline design. |
| `CCDC v1 Web Browsing Outbound` | Outbound TCP 80 and 443 | Linked for Domain Computers and Domain Controllers. |
| `CCDC v1 Splunk Outbound` | Splunk forwarding and web access | Backup contains outbound TCP 9997 and 8000 rules; runtime updates only the imported firewall registry-policy values to scope both rules to the supplied Splunk address. Static rule fields remain from the draft. |
| `CCDC v1 Domain Audit` | Advanced auditing | The backup contains legacy audit values and an `audit.csv` with 18 advanced subcategories. Runtime registers the imported CSV with Windows' native Audit Configuration extension. No startup script is used. |
| `CCDC v1 ADCS Access` | AD CS service access | Selected CA computers. |
| `CCDC v1 MSSQL Role` | Default-instance SQL access | Selected database computers. |
| `CCDC v1 FTP Access` | IIS FTP access | Static service/firewall settings and the passive-range scheduled task are in the backup; runtime removes the legacy authentication startup script before linking to selected FTP computers. Anonymous authentication remains locally managed. |
| `CCDC v1 Mail Firewall Role` | Mail firewall profile | Selected mail computers. |
| `CCDC v1 Web Firewall Role` | IIS web-server profile | Backup contains separate HTTP.sys-scoped inbound TCP 80/443 rules and automatic startup for W3SVC and WAS; linked to selected web computers. |
| `CCDC v1 RDP Access` | RDP service and user access | Static RDP/firewall settings are in the backup. Runtime adds Domain Users to Remote Desktop Users and writes the current domain SID into the logon right. |
| `CCDC v1 SSH Access` | Windows OpenSSH service, firewall, and access for all domain users | Static firewall/service settings and the startup script are in the backup. Runtime removes the C22-specific PowerShell startup path and writes `scripts.ini` for the imported GPO ID. |
| `CCDC v1 WinRM Access` | WinRM listener and user access | Static listener/firewall settings are in the backup. Runtime adds Domain Users to `Remote Management Users` using the current domain SID. |
| `CCDC v1 SMB Access` | SMB service and anonymous-access controls | Service startup, TCP 445, guest-account, and anonymous-access settings are in the backup. |
| `CCDC v1 Linux SSH Logon` | SSSD logon right for Linux SSH | The backup contains no C22 domain SID; runtime writes the current domain users/admins into the logon right. |
| `CCDC v1 SQL Browser Access` | SQL Browser service access | Windows-exported backup; all package backups were import-verified on Server 2016, 2019, 2022, and 2025. No new GPOs were linked during import validation. |
| `CCDC v1 Ping Access` | ICMP echo access | Selected computers. |
| `CCDC v1 SNMP Access` | SNMP service/firewall profile | Selected computers. |
| `CCDC v1 XAMPP Ports` | XAMPP web ports | Selected computers. |
| `CCDC v1 MySQL-MariaDB Ports` | MySQL/MariaDB ports | Selected computers. |

The authoritative list of importable backups and split assignment is maintained in the adjacent `gpo-v1/expanded-draft-package/BACKUP-MANIFEST.md`. All 24 policies have Windows-exported backups. The existing full package imported on DC2016, DC2019, DC2022, and DC2025 as temporary unlinked GPOs; the split ZIPs preserve those backup folders, but have not yet been separately imported on Windows. Package-import validation is distinct from policy application or effective-policy verification.

## Runtime customization

The script may modify an imported draft GPO for run-specific values: domain SIDs, Splunk and CA addresses, SSH startup paths, selected computer filters, or named firewall-port exceptions based on an imported draft template. It registers the Domain Audit CSV from the imported backup with the native Audit Configuration extension. FTP startup cleanup removes the legacy authentication script after import. Additional port exceptions must also begin from an importable draft GPO; the runner must not create a new GPO from scratch.

When a draft package cannot be fetched or validated, the GPO stage is skipped with an error/status report. Independent non-GPO actions such as password/account changes continue. The runner does not fall back to the legacy archive or author policies through PowerShell.

## Source paths

- Orchestration, prompts, default role ordering, and draft source parameters: `Public/Invoke-DomainHardening.ps1` (`Invoke-DomainHardening`).
- Draft URI/path resolution, download/extraction, import and security-filter logic: `Public/GPO/GpoHelpers.ps1` (`Initialize-CcdcGpoDraftEnvironment`, `Import-CcdcGpo`, `Add-CcdcGpoLink`, `Set-CcdcGpoSecurityFilter`).
- Domain and DC policy linking: `Public/GPO/Link-DcAllowAdGpo.ps1`, `Link-DomainFirewallGpo.ps1`, `Link-DomainGpoUpdateInterval.ps1`, `Link-DomainGoodGpo.ps1`, `Link-DomainAuditGpo.ps1`, and `Link-DomainSplunkOutboundGpo.ps1`.
- Draft-backed server roles: `Public/GPO/Link-ServerRoleGpo.ps1`.
- Runtime edits to imported draft role policies: `Public/GPO/GpoHelpers.ps1` (`$script:CcdcServiceRoles`, `Add-CcdcServiceRoleGpo`); linking wrappers are in `Link-ServerServiceGpo.ps1`, `Link-ServerWinRMGpo.ps1`, `Link-SqlBrowserGpo.ps1`, and `Link-WebBrowsingGpo.ps1`.
- Per-computer port exceptions: `Public/GPO/DomainFirewallPortRules.ps1`.
- Draft backup inventory: `../../gpo-v1/expanded-draft-package/BACKUP-MANIFEST.md`.

`Enable-AdvancedAuditing` in `Public/TH-IR/Enable-AdvancedAuditing.ps1` is a local script function, not a GPO currently linked by `Invoke-DomainHardening`.

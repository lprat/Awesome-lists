# Awesome list security
## CVE
 - CISA exploited vuln: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 - ANSSI Alerte: https://www.cert.ssi.gouv.fr/alerte/
 - OpenCVE: https://www.opencve.io/welcome
 - Twitter CVE hashtag: https://twitter.com/hashtag/cve
## Tactics and techniques 
 - https://pbom.dev/
 - https://attack.mitre.org/
## Signature
 - File (Yara): 
    - https://github.com/Yara-Rules
    - https://github.com/InQuest/awesome-yara
 - Event (SIGMA): https://github.com/SigmaHQ/sigma
 - Network (Snort/Suricata): https://rules.emergingthreats.net/
 - Antivirus: https://github.com/Cisco-Talos/clamav
 - HashR: https://github.com/google/hashr
 - Tls  fingerprint: https://github.com/salesforce/jarm & https://github.com/salesforce/ja3
 - Sysmon Rules: https://github.com/Neo23x0/sysmon-config
 - Auditd Rules: https://github.com/Neo23x0/auditd
## Detect tools
 - https://github.com/jertel/elastalert2
 - https://github.com/palantir/osquery-configuration
 - https://github.com/ANSSI-FR/AnoMark
 - https://github.com/Thijsvanede/DeepLog
## Honeypot
 - tpotce: https://github.com/telekom-security/tpotce
 - canarytokens: https://github.com/thinkst/canarytokens-docker
 - cowrie (ssh/telnet): https://github.com/cowrie/cowrie
 - opencanary: https://github.com/thinkst/opencanary
## Collect tools
 - Forensics Artifact list: https://github.com/ForensicArtifacts/artifacts
 - Windows collect: https://dfir-orc.github.io/
 - linux & Windows & Mac collect: https://github.com/lprat/spyre/
 - Linux:
   - https://github.com/lprat/EAL
   - https://github.com/FSecureLABS/LinuxCatScale
   - https://github.com/tclahr/uac
 - AD timeline: https://github.com/ANSSI-FR/ADTimeline
 - Vsphere: https://github.com/ANSSI-FR/DFIR4vSphere
 - O365:
   - https://github.com/ANSSI-FR/DFIR-O365RC
   - https://github.com/CrowdStrike/CRT
## Quarantine extract
 - Dexray: http://hexacorn.com/d/DeXRAY.pl
## Analyze artifacts
 - IntelOwl: https://github.com/intelowlproject/IntelOwl
 - Static file analysis: https://github.com/lprat/static_file_analysis/
 - Cyberchef: https://github.com/gchq/CyberChef
 - website: https://github.com/buffer/thug
 - Binary:
   - https://github.com/rizinorg/cutter && https://github.com/radareorg/radare2
   - https://github.com/NationalSecurityAgency/ghidra
   - https://github.com/cmu-sei/pharos
   - Capacities: https://github.com/mandiant/capa & https://git.sr.ht/~prabhu/blint
   - https://github.com/mandiant/speakeasy
 - Sandbox: https://github.com/cuckoosandbox/cuckoo & https://github.com/hatching/vmcloak
## Memory analysis
 - Volatility: https://github.com/volatilityfoundation/volatility3
## MBR/VBR analysis
 - https://github.com/ANSSI-FR/bootcode_parser 
## Make timeline
 - Plaso: https://plaso.readthedocs.io/en/latest/
## Timeline analysis
 - Timesketch: https://github.com/google/timesketch/
## Hardening
### Audit/Compliance
 - AD : https://www.pingcastle.com/
 - vsphere: https://github.com/DaftPyPosh/vSphereSCG
 - Container compliance: https://github.com/deepfence/compliance
 - Openscap: https://github.com/OpenSCAP/openscap
 - Linux compliance: https://github.com/ComplianceAsCode/content
 - Ansible collection hardening: https://github.com/dev-sec/ansible-collection-hardening
 - Git Leaks: https://github.com/zricethezav/gitleaks
 - Secrets leaks in git/s3/file/syslog/... : https://github.com/trufflesecurity/trufflehog
 - CIS (https://www.cisecurity.org/cis-benchmarks/):
   - https://github.com/CISOfy/lynis
   - https://github.com/ovh/debian-cis
   - https://github.com/dev-sec/cis-dil-benchmark
   - https://github.com/dev-sec/cis-docker-benchmark
   - https://github.com/dev-sec/cis-kubernetes-benchmark
   - https://github.com/aquasecurity/chain-bench
   - https://github.com/prowler-cloud/prowler
   - https://github.com/cloud-custodian/cloud-custodian/
   - https://github.com/Checkmarx/kics
 - AV/EDR: https://github.com/NextronSystems/APTSimulator
 - NIDS: https://github.com/3CORESec/testmynids.org
 - Waf:
   - https://github.com/microsoft/WAFBench
   - https://github.com/wallarm/gotestwaf
 - Container vulnerabilities scan
   - https://github.com/aquasecurity/trivy
   - https://github.com/anchore/anchore-engine
   - https://github.com/docker/docker-bench-security
   - https://github.com/quay/clair
 - check vulnerabilties in infrastructure as code/container
   - https://github.com/bridgecrewio/checkov
   - https://github.com/tenable/terrascan
   - https://github.com/aquasecurity/kube-hunter
 - kubernetes check security
   - https://github.com/aquasecurity/kube-bench
   - https://github.com/aquasecurity/kube-hunter
   - https://kubesec.io/
 - systemd check security: https://github.com/alegrey91/systemd-service-hardening & https://blog.ilearned.eu/systemd-sandboxing.html
### Linux
 - Docker filter egress to internet: https://bearstech.com/societe/blog/dns-my-fw/
 - Linux sandbox firejail: https://github.com/netblue30/firejail
 - Syscall2secomp: https://github.com/aquasecurity/kube-hunter
 - Apparmor profil generator: https://github.com/genuinetools/bane
 - Container hardening:
    - Container as VM:
      - https://katacontainers.io/
      - https://gvisor.dev/
    - Network policy exemples: https://github.com/ahmetb/kubernetes-network-policy-recipes
### Windows
 - https://github.com/securitywithoutborders/hardentools
 - https://github.com/simeononsecurity/Standalone-Windows-Server-STIG-Script
 - https://github.com/simeononsecurity/Standalone-Windows-STIG-Script
 - https://github.com/Sycnex/Windows10Debloater
 - https://github.com/nsacyber/Windows-Secure-Host-Baseline
####??AD
 - https://github.com/davidprowe/AD_Sec_Tools
 - https://github.com/mtth-bfft/adeleg
 - Check list ANSSI: https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html
 - PAW (machine d??di?? ?? l'administration): https://learn.microsoft.com/fr-fr/security/compass/privileged-access-devices
 - FGPP (https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt) strategie de mots de passe afin??e
 - LAPS (Local Administrator Password Solution)
 - GMSA - Group Managed Service Accounts (https://www.it-connect.fr/active-directory-utilisation-des-gmsa-group-managed-service-accounts/) - compte de service
 - JEA powershell (https://learn.microsoft.com/fr-fr/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.3) - d??leguer des droits powershell sur une machine pour eviter de donner des acc??s admin
 - ETW log: https://github.com/Processus-Thief/ETWMonitor/blob/main/ETWMonitor%20Agent/ETWService/rules.xml
 - Save AD from cmd.exe (admin) to USB (e:):
```
NTDSUtil
Activate instance NTDS
ifm
Create SYSVOL full E:
```
### web
 - https://github.com/bunkerity/bunkerweb
### DB
 - https://github.com/cossacklabs/acra
### SMTP
 - https://github.com/Neomediatech/rspamd
 - https://github.com/HeinleinSupport/olefy
### Dev
 - Global
   - https://github.com/airbus-seclab/c-compiler-security
   - https://github.com/AppThreat/dep-scan
   - https://semgrep.dev/playground/new
   - https://github.com/eth0izzle/shhgit (secrets in source code)
 - Golang:
   - https://github.com/securego/gosec
   - https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
   - https://github.com/sonatype-nexus-community/nancy
 - Python: pep8
 - Php: rix (sonarqub)
 - C: Splint
## Pentest
### Global
  - https://github.com/swisskyrepo/PayloadsAllTheThings/
### Labs
  - Kubernetes goat (lab vuln kubernetes): https://github.com/madhuakula/kubernetes-goat
  - Badblood (fills AD domain with structure and thousands of objects): https://github.com/davidprowe/BadBlood
  - Detectionlab (windows lab): https://github.com/clong/DetectionLab
### Linux
  - Sudo killer: https://github.com/TH3xACE/SUDO_KILLER
  - Find secrets and passwords in container images and file systems: https://github.com/deepfence/SecretScanner/
### DNS
  - DNSchef (DNS proxy for Penetration Testers and Malware Analysts): https://github.com/iphelix/dnschef
### AD
  - https://github.com/BloodHoundAD/BloodHound
  - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
  - https://github.com/AlsidOfficial/WSUSpendu
  - https://github.com/Group3r/Group3r
### Web
  - https://portswigger.net/web-security
### DB
  - oracle: https://github.com/quentinhardy/odat
  - nosqlmap: https://github.com/codingo/NoSQLMap
  - sqlmap: https://sqlmap.org/
### Network
  - Responder: https://github.com/lgandx/Responder
  - bettercap: https://github.com/bettercap/bettercap
### Wifi
  - wifiphisher: https://github.com/wifiphisher/wifiphisher
  - wifite2: https://github.com/derv82/wifite2
### Payload
  - Payload pentest: https://github.com/swisskyrepo/PayloadsAllTheThings
### Dev
 - Decompilation: https://github.com/avast/retdec
 - DBI:
   - https://github.com/hasherezade/tiny_tracer
   - https://github.com/mxmssh/drltrace
   - https://github.com/frida/frida


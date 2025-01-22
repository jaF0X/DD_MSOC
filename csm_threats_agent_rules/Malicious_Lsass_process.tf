resource "datadog_csm_threats_agent_rule" "RD_malicious_lsass_process" {
  name        = "RD_malicious_lsass_process"
  enabled     = true
  description = "Only one instance of LSASS.exe should be present on a system. It is started within second of system boot from the C:\Windows\System32 folder with Wininit.exe as its parent. Any deviation is non-standard."
  expression  = "exec.file.name == "lsass.exe" && (process.parent.file.path != "C:\Windows\System32\wininit.exe" || process.file.path != "C:\Windows\System32\lsass.exe")"
}
resource "datadog_csm_threats_agent_rule" "RD_malicious_explorer_process" {
  name        = "RD_malicious_explorer_process"
  enabled     = true
  description = "Explorer.exe starts upon an interactive user logon. There can be more than one instance running per user. However, the legitimate Explorer.exe resides within the system root — likely “C:\Windows” on most machines — and not within the C:\Windows\System32 folder."
  expression  = "exec.file.name == "explorer.exe" && process.file.path != "C:\Windows\explorer.exe""
}
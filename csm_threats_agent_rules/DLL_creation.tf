resource "datadog_csm_threats_agent_rule" "RD_dll_creation" {
  name        = "RD_dll_creaiton"
  enabled     = true
  description = "New DLLs populating within a core Windows directory should be investigated for maliciousness."
  expression  = "create.file.name =~ "*.dll" && create.file.path in ["C:\Windows", "C:\Windows\System32\*", "C:\Windows\SysWOW64\*", "C:\Users\*\AppData\*", "C:\Windows\WinSxS\*"]"
}
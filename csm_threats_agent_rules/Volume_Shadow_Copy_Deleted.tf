resource "datadog_csm_threats_agent_rule" "RD_volume_shadow_copy_deleted" {
  name        = "RD_volume_shadow_copy_deleted"
  enabled     = true
  description = "There are legitimate purposes for Administrators to manually delete Shadow Copies and Windows systems will remove outdated versions as it creates new stores. Some ransomware strains are known to locate these stores and delete them to prevent system recovery."
  expression  = "process.file.name in ["*powershell*" , "pwsh.exe" , "cmd.exe"] && exec.cmdline ~= "*vssadmin delete shadows*""
}
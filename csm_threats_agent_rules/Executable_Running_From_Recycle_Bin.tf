resource "datadog_csm_threats_agent_rule" "RD_executable_running_from_recycle_bin" {
  name        = "RD_executable_running_from_recycle_bin"
  enabled     = true
  description = "No application should be executing from the Recycle Bin."
  expression  = "exec.file.name =~ "*.exe" && process.parent.file.path =~ "C:\$Recycle.Bin\*""
}
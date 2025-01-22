resource "datadog_csm_threats_agent_rule" "RD_office_app_spawning_child_process" {
  name        = "RD_office_app_spawning_child_process"
  enabled     = true
  description = "Office applications can temporarily spawn child processes, like when a user opens dynamic content from within a doucment. However, this is a common method attacks use to gain initial access into an environment and should be monitored."
  expression  = "(exec.file.name =~ "*.exe" && exec.file.name not in ["powershell.exe" , "pwsh.exe" , "cmd.exe"]) && process.parent.file.name in ["*word*","*excel*","*powerpnt*"]"
}
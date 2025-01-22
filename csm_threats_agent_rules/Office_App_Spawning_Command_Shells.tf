resource "datadog_csm_threats_agent_rule" "RD_office_app_spawning_command_shells" {
  name        = "RD_office_app_spawning_command_shells"
  enabled     = true
  description = "Office applications should never open command prompts. This is a common method attackers use to execute malicious code in the background."
  expression  = "exec.file.name in ["powershell.exe" , "pwsh.exe" , "cmd.exe"] && process.parent.file.name in ["*word*","*excel*","*powerpnt*"]"
}
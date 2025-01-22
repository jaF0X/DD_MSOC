resource "datadog_csm_threats_agent_rule" "RD_executable_running_from_TEMP_folder" {
  name        = "RD_executable_running_from_TEMP_folder"
  enabled     = true
  description = "Folders labeled as temporary use locations with executables running from within them, anywhere on the system, are non-standard and should be investigated."
  expression  = "exec.file.name =~ "*.exe" && process.file.path in ["C:\*\Users\*\Temp" , "C:\Windows\Temp" , "$:\*\Temp" , "$:\Temp" ]"
}
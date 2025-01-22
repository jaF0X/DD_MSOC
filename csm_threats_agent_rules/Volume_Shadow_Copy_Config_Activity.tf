resource "datadog_csm_threats_agent_rule" "RD_volume_shadow_copy_config_activity" {
  name        = "RD_volume_shadow_copy_config_activity"
  enabled     = true
  description = "Regular users likely have no reason to query Volume Shadow Copy location, size, existence, or other details. Some ransomware strains are known to locate these stores and delete them to prevent system recovery."
  expression  = "process.file.name in ["*powershell*" , "pwsh.exe", "cmd.exe"] && exec.cmdline in ["*vssadmin list shadows*","*vssadmin list shadowstorage*","*vssadmin add shadowstorage*","*vssadmin resize shadowstorage*","*wmic shadowcopy*" ,"*Get-WmiObject -Class Win32_ShadowCopy*"]"
}
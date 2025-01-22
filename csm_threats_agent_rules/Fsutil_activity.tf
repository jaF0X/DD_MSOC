resource "datadog_csm_threats_agent_rule" "RD_fsutil_activity" {
  name        = "RD_fsutil_activity"
  enabled     = true
  description = "Bad actors can abuse this preexisting tool for granular file system manipulation."
  expression  = "process.file.name in [ "*powershell*", "pwsh.exe", "cmd.exe"] && exec.cmdline =~ "*fsutil*""
}
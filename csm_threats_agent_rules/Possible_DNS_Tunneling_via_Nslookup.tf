resource "datadog_csm_threats_agent_rule" "RD_possible_dns_tunneling_via_nslookup" {
  name        = "RD_possible_dns_tunneling_via_nslookup"
  enabled     = true
  description = "nslookup.exe can be used to tunnel data out of an environment"
  expression  = "process.file.name =="nslookup.exe" && exec.cmdline in ["-qt=*" , "-q=*", "-type=*" , "-querytype=*"]"
}
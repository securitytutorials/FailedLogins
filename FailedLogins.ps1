
# Past number of hours is how meany hours back you want to search in the security log 
$Past_n_Hours = [DateTime]::Now.AddHours(-3)

# Collect Failed login events (4625) from the security log 
$badRDPlogons = Get-EventLog -LogName 'Security' -after $Past_n_Hours -InstanceId 4625 | ?{$_.Message -match 'logon type:\s+(3)\s'} | Select-Object @{n='IpAddress';e={$_.ReplacementStrings[-2]} }

# Pull out the Ip Addresses of the failed logins
$getip = $badRDPlogons | group-object -property IpAddress | where {$_.Count -gt 5} | Select -property Name

# Creates Log
$log = "C:\FailedLogins\rdp_blocked_ip.txt"

#Takes the current IPs already in the block list
$current_ips = (Get-NetFirewallRule -DisplayName "CUSTOM RDP BLOCK" | Get-NetFirewallAddressFilter ).RemoteAddress

#Takes each IP captured and adds it to log
foreach ($ip in $getip)
{
  # avoid duplicates ip
  if (-Not ($current_ips -match $ip.name))
    {
      $current_ips += $ip.name
      (Get-Date).ToString() + ' ' + $ip.name + ' The IP address has been blocked due to ' + ($badRDPlogons | where {$_.IpAddress -eq $ip.name}).count + ' attempts for 2 hours'>> $log # writing the IP blocking event to the log file
     }
}

#Adds current ips to the CUSTOM RDP BLOCK rule
Set-NetFirewallRule -DisplayName "CUSTOM RDP BLOCK" -RemoteAddress $current_ips

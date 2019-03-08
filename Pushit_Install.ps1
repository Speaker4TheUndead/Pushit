Function Pushit{
<#
.SYNOPSIS
    This is a TCP port-scanning tool called Pushit.

.DESCRIPTION
    Trys to make a TCP connection with a host(s) on specified port(s).

.PARAMETER Target_Ip
    The parameter Target_Ip can be a single ip address.

.PARAMETER Target_Ip_Range
    The parameter Target_Ip_Range can be a range of ip addresses within a CLASS C Network (Ex: 192.168.1.10-45).

.PARAMETER Target_Cidr_Range
    The parameter Target_Cidr_Range can be a range of ip addresses denoted in CIDR notation (Ex: 192.168.1.1/24).

.PARAMETER Target_Ports
    The parameter Target_Ports specifies one or more ports delimmited by commas to attempt to scan (Ex: 1540, 3000, 80).

.PARAMETER Target_Port_Range
    The parameter Target_Port_Range specifies a range of ports to scan (Ex: 24-500).

.EXAMPLE
    Port-Poker -target_ip "192.168.1.3" -target_ports 80, 8080, 9000
.NOTES
    Author: Johnse Chance
    Last Edit: 2019-03-08
    Version 1.0 - initial release of Pushit
#>
[CmdletBinding()]
<#Just Input Validation, Nothing to See Here#>
Param (
    [Parameter(ParameterSetName="ip_plus_port_range", Position=0, Mandatory=$True)]
    [Parameter(ParameterSetName="ip_plus_port", Position=0, Mandatory=$True)][ValidatePattern("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$target_ip,
    
    [Parameter(ParameterSetName="cidr_plus_port_range", Position=0, Mandatory=$True)]
    [Parameter(ParameterSetName="cidr_plus_port", Position=0, Mandatory=$True)][ValidatePattern("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(3[0-2]|[1-2]?[0-9]))$")]
    [string]$target_cidr_range,

    [Parameter(ParameterSetName="iprange_plus_port_range", Position=0, Mandatory=$True)]
    [Parameter(ParameterSetName="iprange_plus_port", Position=0, Mandatory=$True)][ValidatePattern("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-\d\d?\d?$")]
    [ValidateScript({
        $_ -match '\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(\d\d?\d?)$';
        $low = [int]$Matches[1]
        $high = [int]$Matches[2]
        if(($low -ge $high )-Or ($low -NotIn 0..255) -Or ( $high -NotIn 0..255)){
            throw "Invalid Last Octet Range (Must be within 0-255)";
        }else{
            return $true
        }
    })]
    [string]$target_ip_range,


    [Parameter(ParameterSetName="ip_plus_port_range", Position=1, Mandatory=$True)]
    [Parameter(ParameterSetName="iprange_plus_port_range", Position=1, Mandatory=$True)]
    [Parameter(ParameterSetName="cidr_plus_port_range", Position=1, Mandatory=$True)]
    [ValidateScript({
        $_ -match '(\d+)\-(\d+)$';
        $low = [int]$Matches[1];
        $high = [int]$Matches[2];
        if(($low -ge $high) -or ($low -NotIn 0..65535) -or ($high -NotIn 0..65535)){
            throw "Invalid Port Range (Must be within 0-65535)";
        }else{
            return $true
        }
    })]
    [string]$target_port_range,

    [Parameter(ParameterSetName="ip_plus_port", Position=1, Mandatory=$True)]
    [Parameter(ParameterSetName="iprange_plus_port", Position=1, Mandatory=$True)]
    [Parameter(ParameterSetName="cidr_plus_port", Position=1, Mandatory=$True)]
    [ValidateCount(1, 65536)][ValidateRange(0, 65535)]
    [int32[]]$target_ports
) 
<#End Input Validation#>

<#Case by Case Setup#> 
$ips = @()
$ports = @()
Switch($PSCmdlet.ParameterSetName){
   "ip_plus_port" {
        <#Add IP Address#>
        $ips += ,$target_ip;
        <#Add Ports#>
        Foreach($portyboi in $target_ports){$ports += ,$portyboi;}        
   }
   "ip_plus_port_range"{
        <#Add IP Address#>
        $ips += ,$target_ip;
        <#Add Ports#>
        $target_port_range -match '(\d+)\-(\d+)$';
        $low_port = $Matches[1];
        $high_port = $Matches[2];
        Foreach($portyboi in $low_port..$high_port){$ports += ,$portyboi;}
   }
   "iprange_plus_port"{
        <#Main Loop to Add IP Addresses#>
        $target_ip_range -match '(.*\.)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(\d\d?\d?)$';
        $beginning = [string]$Matches[1]
        $low = [int]$Matches[2]
        $high = [int]$Matches[3]
        Foreach($ipboi in $low..$high){$ips += ,(""+$beginning+$ipboi.toString());}
        <#Add Ports#>
        Foreach($portyboi in $target_ports){$ports += ,$portyboi;}
   }
   "iprange_plus_port_range"{
        <#Main Loop to Add IP Addresses#>
        $target_ip_range -match '(.*\.)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\-(\d\d?\d?)$';
        $beginning = [string]$Matches[1]
        $low = [int]$Matches[2]
        $high = [int]$Matches[3]
        Foreach($ipboi in $low..$high){$ips += ,(""+$beginning+$ipboi.toString());}
        <#Add Ports#>
        $target_port_range -match '(\d+)\-(\d+)$';
        $low_port = $Matches[1];
        $high_port = $Matches[2];
        Foreach($portyboi in $low_port..$high_port){$ports += ,$portyboi;}
   }
   "cidr_plus_port" {
        $target_cidr_range -match '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2]?[0-9])$';
        [uint32[]]$octets = $Matches[1..4];
        [uint32]$ipnumber = [uint32](((([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16)) -bor ([uint32]$octets[2] -shl 8)) -bor ([uint32]$octets[3]));
        [int]$maskbits = [int]$Matches[5];
        Write $maskbits
        [uint32]$mask = 0x7fffffff;
        $mask = [uint32]($mask -shl (32 - ($maskbits)));
        [uint32]$ipstart = [uint32]$ipnumber -band $mask;
        [uint32]$ipend = [uint32]$ipnumber -bor ($mask -bxor [uint32]0x7fffffff); 
        [uint32[]]$newstartocts = [uint32]($ipstart -shr 24), ([uint32]($ipstart -shr 16) -band [uint32]0xff), ([uint32]($ipstart -shr 8) -band [uint32]0xff), ([uint32]$ipstart -band [uint32]0xff);
        [uint32[]]$newendocts = [uint32]($ipend -shr 24), ([uint32]($ipend -shr 16) -band [uint32]0xff), ([uint32]($ipend -shr 8) -band [uint32]0xff), ([uint32]$ipend  -band [uint32]0xff);
        <#Main Loop to Add IP Addresses#>
        $i = $newstartocts[0];
        $j = $newstartocts[1];
        $k = $newstartocts[2];
        $l = $newstartocts[3];
        while($i -le $newendocts[0]){
            while(($i -le $newendocts[0]) -or ($j -le $newendocts[1])){
                if($j -eq 256){break}
                while(($i -le $newendocts[0]) -or ($j -le $newendocts[1]) -or ($k -le $newendocts[2])){
                    if($k -eq 256){break}
                    while(($i -le $newendocts[0]) -or ($j -le $newendocts[1]) -or ($k -le $newendocts[2]) -or ($l -le $newendocts[3])){
                        if($l -eq 256){break}
                        $ips += ,($i.ToString() + "." + $j.ToString() + "." + $k.ToString() + "." + $l.ToString());  
                        $l++;
                    }
                    $k++;
                }
                $j++;
            }
            $i++;
        }
        <#Add Ports#>
        Foreach($portyboi in $target_ports){$ports += ,$portyboi;}
   }
   "cidr_plus_port_range" {
        $target_cidr_range -match '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2]?[0-9])$';
        [uint32[]]$octets = $Matches[1..4];
        [uint32]$ipnumber = [uint32](((([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16)) -bor ([uint32]$octets[2] -shl 8)) -bor ([uint32]$octets[3]));
        [int]$maskbits = [int]$Matches[5];
        Write $maskbits
        [uint32]$mask = 0x7fffffff;
        $mask = [uint32]($mask -shl (32 - ($maskbits)));
        [uint32]$ipstart = [uint32]$ipnumber -band $mask;
        [uint32]$ipend = [uint32]$ipnumber -bor ($mask -bxor [uint32]0x7fffffff); 
        [uint32[]]$newstartocts = [uint32]($ipstart -shr 24), ([uint32]($ipstart -shr 16) -band [uint32]0xff), ([uint32]($ipstart -shr 8) -band [uint32]0xff), ([uint32]$ipstart -band [uint32]0xff);
        [uint32[]]$newendocts = [uint32]($ipend -shr 24), ([uint32]($ipend -shr 16) -band [uint32]0xff), ([uint32]($ipend -shr 8) -band [uint32]0xff), ([uint32]$ipend  -band [uint32]0xff);
        <#Main Loop to Add IP Addresses#>
        $i = $newstartocts[0];
        $j = $newstartocts[1];
        $k = $newstartocts[2];
        $l = $newstartocts[3];
        while($i -le $newendocts[0]){
            while(($i -le $newendocts[0]) -or ($j -le $newendocts[1])){
                if($j -eq 256){break}
                while(($i -le $newendocts[0]) -or ($j -le $newendocts[1]) -or ($k -le $newendocts[2])){
                    if($k -eq 256){break}
                    while(($i -le $newendocts[0]) -or ($j -le $newendocts[1]) -or ($k -le $newendocts[2]) -or ($l -le $newendocts[3])){
                        if($l -eq 256){break}
                        $ips += ,($i.ToString() + "." + $j.ToString() + "." + $k.ToString() + "." + $l.ToString());  
                        $l++;
                    }
                    $k++;
                }
                $j++;
            }
            $i++;
        }
        <#Add Ports#>
        $target_port_range -match '(\d+)\-(\d+)$';
        $low_port = $Matches[1];
        $high_port = $Matches[2];
        Foreach($portyboi in $low_port..$high_port){$ports += ,$portyboi;}
   }
}
<#End Case by Case Setup#>


<#The Actual Port Scanning#>
Foreach($ipboi in $ips){
    Foreach($portyboi in $ports){Test-NetConnection -ComputerName $ipboi -Port $portyboi}
}
<#The End ;#>
}

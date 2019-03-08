# Pushit
A Powershell TCP Port Scanner

.SYNOPSIS
    A TCP port-scanning Tool called Pushit.

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

# Records USB traffic between the Windows Neat driver and an ND-1000 with USBPcap
# (installed with Wireshark). Run from an administrator PowerShell.
#
#   .\record.ps1 -Name scan1 -Device 4          # only the scanner (find its address with
#                                                # the --extcap-config command below)
#   .\record.ps1 -Name plugin1 -All             # every device on the controller, e.g. when
#                                                # re-plugging changes the scanner's address
#
# USBPcapCMD returns to the prompt immediately and keeps recording in the background.
# Stop it with:  taskkill /IM USBPcapCMD.exe /T /F
# List devices:  & 'C:\Program Files\Wireshark\extcap\USBPcapCMD.exe' --extcap-interface '\\.\USBPcap1' --extcap-config
param([string]$Name = 'capture1', [int]$Device = 0, [switch]$All,
      [string]$Interface = '\\.\USBPcap1', [string]$OutDir = $PSScriptRoot)
if (-not $All -and -not $Device) { throw 'Pass -Device <address> or -All' }
$out = Join-Path $OutDir "$Name.pcap"
Write-Host "Recording USB traffic to $out"
$which = if ($All) { @('-A') } else { @('--devices', "$Device") }
& 'C:\Program Files\Wireshark\extcap\USBPcapCMD.exe' -d $Interface @which --inject-descriptors -s 4194304 -b 134217728 -o $out

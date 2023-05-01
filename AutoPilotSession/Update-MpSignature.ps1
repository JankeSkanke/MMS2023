#Update Defender 
try {
   Update-MpSignature
   exit 0
}
catch {
    exit 0<#Do this if a terminating exception happens#>
}
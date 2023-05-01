<#
.SYNOPSIS
    Remove built-in apps (modern apps) from Windows 11 for All Users.

.DESCRIPTION
    This script will remove all built-in apps that are specified in the 'AppsToRemove' variable.
    The control file (txt file) is hosted in Azure Blob storage or GitHub so it can be dynamically updated.
    Built-in apps listed in the txt file that are NOT prefixed with a # will be removed.
    
    ##WARNING## 
    Use with caution, restoring deleted provisioning packages is not a simple process.

    ##TIP##
    If removing "MicrosoftTeams", also consider disabling the "Chat" icon on the taskbar, using Intune settings catalog, as clicking this will re-install the appxpackage for the user.
    Script is intended to run silently from Intune and as such output from script is limited. 

.EXAMPLE
    Example below will remove Microsoft.Xbox.TCUI and keep Microsoft.WindowsTerminal
    #Microsoft.WindowsTerminal
    Microsoft.Xbox.TCUI  

.NOTES
    Idea based on an original script for Windows 10 app removal / Credit to: Nickolaj Andersen @ MSEndpointMgr
    Modifications to original script to clearly define what to remove rather than Whitelisting what to keep

    FileName:    Remove-Appx-AllUsers-CloudSourceList.ps1
    Author:      Ben Whitmore / Jan Ketil Skanke
    Contact:     @byteben / @JankeSkanke
    Date:        27th June 2022
    Updated:     2022-21-09

    Version history:
    1.0.0 - (2022-27-06)    Script created
    2.0.0 - (2022-21-09)    Script logic updated to use #<AppName> in control file for keeping apps instead of removing apps. 

#>

Begin {
    $Script:LogFileName="Remove-Apps-Allusers.log"
    # Define apps that should never be removed regardless of control file. This is meant as a failsafe and must be modified here in the script
    # Apps defined by author is Microsoft.WindowsStore, Microsoft.UI.Xaml.2.4 and Microsoft.VCLibs.140.00 as the store should be kept with dependencies
    $Script:SafeGuardAppList=@(
        'Microsoft.WindowsStore'
        'Microsoft.UI.Xaml.2.4'
        'Microsoft.VCLibs.140.00'
    )
    #Log Function
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
            [parameter(Mandatory = $false, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = $LogFileName
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path $env:SystemRoot -ChildPath $("Temp\$FileName")
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($LogFileName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
            if ($Severity -eq 1) {
                Write-Verbose -Message $Value
            } elseif ($Severity -eq 3) {
                Write-Warning -Message $Value
            }
        } catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $LogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }#endfunction
    
    #Function to Remove AppxProvisionedPackage
    Function Remove-AppxProvisionedPackageCustom {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$AppToRemove
        )
        # Attempt to remove AppxProvisioningPackage
        try {       
            # Get Package Name
            $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $AppToRemove } | Select-Object -ExpandProperty PackageName -First 1
            Write-LogEntry -Value "$($AppToRemove) found. Attempting removal" -Severity 1

            # Attempt removeal
            $RemoveAppx = Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -AllUsers
                
            #Re-check existence
            $AppProvisioningPackageNameReCheck = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $AppToRemove } | Select-Object -ExpandProperty PackageName -First 1

            If ([string]::IsNullOrEmpty($AppProvisioningPackageNameReCheck) -and ($RemoveAppx.Online -eq $true)) {
                Write-LogEntry -Value "$($AppToRemove) removed"
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to remove $($AppToRemove)"
        }
        
    }

    Write-LogEntry -Value "Windows 11 Builtin-Apps removal process started" -Severity 1
    
    # List of Appx Provisioned Packages to Remove for All Users
    $AppsToRemoveURL = $null
    $AppsToRemoveURL = "https://stintune2048.blob.core.windows.net/removebuiltinapp/Applist_w11.txt"
    Write-LogEntry -Value "AppsToRemoveURL:$($AppsToRemoveURL)" -Severity 1
    
    #Attempt to obtain list of Apps to remove
    Try {
        $AppsToRemoveFile = $null
        $AppsToRemoveFile = (New-Object System.Net.WebClient).DownloadString($AppsToRemoveURL)
    } 
    Catch {
        Write-LogEntry -Value $_.Exception -Severity 2
        Write-Warning $_.Exception
    }

    #Read apps from file and split lines and remove apps commented away with #
    $AppsToRemoveConvertToArray = $AppsToRemoveFile -split "`n" | Foreach-Object { $_.trim() } | Where-Object {$_ -notmatch "#"} 
    Write-LogEntry -Value "Listing out apps targeted for removal: " -Severity 1
    
    #Create arraylist of apps to remove
    $AppsToRemoveArray = New-Object -TypeName System.Collections.ArrayList
    Foreach ($App in $AppsToRemoveConvertToArray) {
        If ($App -notin $SafeGuardAppList) {
            If (!([string]::IsNullOrEmpty($App))) {
                $AppsToRemoveArray.AddRange(@($App))
                Write-LogEntry -Value $App -Severity 1
            }
        }
    }

    #Define App Count
    [int]$AppCount = 0

    #OS Check
    $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    Switch -Wildcard ( $OS ) {
        '21*' {
            $OSVer = "Windows 10"
            Write-Warning "This script is intended for use on Windows 11 devices. $($OSVer) was detected..."
            Write-LogEntry -Value "This script is intended for use on Windows 11 devices. $($OSVer) was detected..." -Severity 2
            Exit 1
        }
    }
}

Process {

    If ($($AppsToRemoveArray.Count) -ne 0) {

        Write-LogEntry -Value "$($AppsToRemoveArray.Count) apps are targeted for removal from this device" -Severity 1
        
        #Initialize list for apps not targeted
        $AppNotTargetedList = New-Object -TypeName System.Collections.ArrayList

        # Get Appx Provisioned Packages
        Write-LogEntry -Value "Gathering installed Appx Provisioned Packages" -Severity 1
        $AppArray = Get-AppxProvisionedPackage -Online | Select-Object -ExpandProperty DisplayName

        # Loop through each Provisioned Package
        foreach ($AppToRemove in $AppsToRemoveArray) {

            # Function call to Remove Appx Provisioned Packages defined in the list
            if (($AppToRemove -in $AppArray)) {
                $AppCount ++
                Try {
                    Remove-AppxProvisionedPackageCustom -AppToRemove $AppToRemove -ErrorAction Stop
                }
                Catch {
                    Write-LogEntry -Value "There was an error when attempting to remove $($BlakListedApp)" -Severity 1
                }
            }
            else {
                $AppNotTargetedList.AddRange(@($AppToRemove))
            }
        }

        #Update Output Information
        If (!([string]::IsNullOrEmpty($AppNotTargetedList))) { 
            Write-Output "The following apps were not removed. Either they were already removed or the Package Name is invalid: `n $AppNotTargetedList "
            Write-LogEntry -Value "The following apps were not removed. Either they were already removed or the Package Name is invalid:-"
            Write-LogEntry -Value "$($AppNotTargetedList)"
        }
        If ($AppCount -eq 0) {
            Write-Output `n"No apps were removed. Most likely reason is they had been removed previously."
            Write-LogEntry -Value "No apps were removed. Most likely reason is they had been removed previously."
        }
    }
    else {
        Write-Output "No list of apps to be removed defined in array"
        Write-LogEntry -Value "No list of apps to be removed defined in array" -Severity 2
    }
}
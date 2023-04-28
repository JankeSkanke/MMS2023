
Import-Module Microsoft.Graph.Users
$Users = Get-MgUser -Filter "startswith(displayName,'MMS D')" 

$manager = @{
	"@odata.id" = "https://graph.microsoft.com/v1.0/users/160e014f-1da0-49ea-baae-3c47cfae4b4d"
}
$hiredate = @{
    employeeHireDate = [System.DateTime]::Parse("2023-05-01T01:00:00Z")
}

foreach ($user in $users){
    $userID = $user.Id
    #Set-MgUserManagerByRef -UserId $userID -BodyParameter $manager    
    #Get-MgUserManager -UserId $userID
    #Update-MgUser -UserId $userID -BodyParameter $hiredate
    Get-MgUser -UserId $userId | Select-Object DisplayName, EmployeeHireDate
}
$leavedate = @{
    employeeLeaveDateTime = [System.DateTime]::Parse("2023-05-10T01:00:00Z")
}
Update-MgUser -UserId $userID -BodyParameter $leavedate
Function Renew-vcsaSignedCert {

    <#
    .SYNOPSIS
        Renew the existing VCSA-signed __MACHINE_CERT certificate.
    .DESCRIPTION
        The Renew-vcsaSignedCert will renew the existing VCSA-signed certificate.
    .PARAMETER vcenter
        vCenter Server FQDN or IP address.
    .PARAMETER vc_user
        Your username or SSO administrator (administrator@vsphere.local).
    .PARAMETER vc_pass
        Administrator password.
    .PARAMETER $body
        Duration (in days) - 730 is the maximum allowed.
    .EXAMPLE
        Renew-vcsaSignedCert -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -duration 730
    #>

    param(
            [Parameter(Mandatory = $true)][string]$vcenter,
            [Parameter(Mandatory = $true)][string]$vc_user,
            [Parameter(Mandatory = $true)][secureString]$vc_pass,
            [Parameter(Mandatory = $true)][string]$duration
        )
    
    $ErrorActionPreference = "Stop"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    if (!$duration) { $duration = Read-Host  "Please enter renewal duration in numner of days 730 (2 years) maximum" }
    
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls" 
    $TlsReneweUrl = $BaseTlsUrl + "?action=renew"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
    
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $apiSessionId)
    $headers.Add("Content-Type", "application/json")

    $body = 
    "{
        ""duration"" : ""$duration""
    }"

    $response = Invoke-WebRequest -Method 'POST' -Uri $TlsReneweUrl -Headers $headers -Body $body -SkipCertificateCheck
    $response | ConvertTo-Json
    
    if ($response.BaseResponse.IsSuccessStatusCode -eq "True") {
            Write-Host "VCSA Certificate Renewal was successful!" -ForegroundColor "Green"
            Write-Host "Please allow 5-10 minutes for services to update with the new certificate and restart automatically." -ForegroundColor "Green"
        }
        else {
            Write-Host "VCSA Certificate Renewal was not successful!" -ForegroundColor "DarkRed"
            Write-Host "Please check that all VCSA services are healthy, and retry the operation."
        }
}
# Requires -Module AzureAD

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]
    $TenantID,

    [Parameter()]
    [string]
    $AppDisplayName = "ADFS Rapid Restore Tool"
)

try {
  Connect-AzureAD -TenantID $TenantID  
}
catch {
  'Could not connect to Azure AD: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
  throw
}


# Create Self signed cert
try {
  $temp = $Env:TEMP
  $tmpCertFile = "$temp\$AppDisplayName.cer"

  $notAfter = (Get-Date).AddMonths(12) # Valid for 12 months
  $thumb = (New-SelfSignedCertificate -DnsName $AppDisplayName -CertStoreLocation "cert:\localmachine\My"  `
          -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
          -NotAfter $notAfter).Thumbprint
  Export-Certificate -cert "cert:\localmachine\my\$thumb" -FilePath $tmpCertFile

  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate("$tmpCertFile")
  $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
}
catch {
  'Unable to generate certificate: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
  throw
}

try {
  remove-item $tmpCertFile -Force
}
catch {
  'Could not delete cert file: ' -f $_.Exception.Message | Write-Warning
  throw
}

$Application = New-AzureADApplication -DisplayName $AppDisplayName
New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "AuthCert" `
  -Type AsymmetricX509Cert -Usage Verify -Value $keyValue -EndDate $notAfter.AddDays(-1)

New-AzureADServicePrincipal -AppId $application.AppId

Write-Host "The Application ID to use in the script: " $Application.AppId -ForegroundColor Green
Write-host "The certificate thumbprint to use in the script: " $thumb -ForegroundColor Green
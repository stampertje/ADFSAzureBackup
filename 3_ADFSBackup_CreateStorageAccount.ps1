[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]
    $rgname,

    [Parameter(Mandatory=$True)]
    [string]
    $location,

    [Parameter(Mandatory=$true)]
    [string]
    $appid,

    # If single IP don't use CIDR notation.
    [Parameter()]
    [string]
    $SAFW_CIDR,

    [Parameter()]
    [string]
    $subnetid
)

If ($null -eq (Get-azcontext))
{
  'Not connected to Azure. Please run Login-AzAccount' | Write-Error -ErrorAction Stop
}

If ($null -eq (get-AzResourceGroup -ResourceGroupName $rgname))
{
  try {
    New-AzResourceGroup -ResourceGroupName $rgname -Location $location
  }
  catch {
    'Failed to create Resource Group: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
    throw
  }
}

$saname = "adfs" + (new-guid).ToString().replace("-","").substring(0,16)

try {
  $newsa = New-AzStorageAccount -Name $saname `
    -Location $location `
    -ResourceGroupName $rgname `
    -Skuname Standard_LRS `
    -AllowBlobPublicAccess $false
}
catch {
  'Failed to create storage account: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
  throw
}


#region storageaccount_firewall_rules
$netrules = @()
$netrules += "-ResourceGroupName", $rgname
$netrules += "-StorageAccountName", $saname
$netrules += "-DefaultAction", "Deny"
$netrules += "-Bypass", "AzureServices"

if (-not($subnetid -eq ""))
{
  $netrules += "-VirtualNetworkRule", "(@{VirtualNetworkResourceId=`"$subnetid`";Action=`"allow`"})"
}

try {
  Invoke-Expression "& Update-AzStorageAccountNetworkRuleSet $netrules"  
}
catch {
  'Failed to set network ruleset: ' -f $_.Exception.Message | Write-Error
  throw
}


if (-not($SAFW_CIDR -eq ""))
{
  $SAFW_CIDR = $SAFW_CIDR.Replace("/32","")

  try {
    Add-AzStorageAccountNetworkRule `
    -ResourceGroupName $rgname `
    -AccountName $saname `
    -IPAddressOrRange $SAFW_CIDR
  }
  catch {
    'Failed to add CIDR to storage firewall allowlist: ' -f $_.Exception.Message | Write-Error
    throw
  }
}

#endregion storageaccount_firewall_rules

if ($appid -ne "")
{
  try {
    # grant permissions to SP
    New-AzRoleAssignment -RoleDefinitionName 'Storage Blob Data Contributor' `
      -ApplicationId $appid `
      -Scope $newsa.Id

    New-AzRoleAssignment -RoleDefinitionName 'Reader and Data Access' `
    -ApplicationId $appid `
    -Scope $newsa.Id    
  }
  catch {
    'Failed to set permissions on storage account: ' -f $_.Exception.Message | Write-Error
    throw
  }
}

Write-host "Use this storage account in the script: " $newsa.StorageAccountName -ForegroundColor Green
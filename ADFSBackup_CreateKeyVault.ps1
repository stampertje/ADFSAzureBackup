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
    $kvname,

    [Parameter(Mandatory=$true)]
    [string]
    $appid,

    [Parameter()]
    [string]
    $KVFW_CIDR,

    [Parameter()]
    [string]
    $subnetid
)

If ($null -eq (get-AzResourceGroup -ResourceGroupName $rgname -ErrorAction SilentlyContinue))
{
  try {
    New-AzResourceGroup -ResourceGroupName $rgname -Location $location
  }
  catch {
    'Failed to create Resource Group: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
    throw
  }
}

#region kv_firewall_rules
  $netrules = @()
  $netrules += "-DefaultAction", "Deny" 
  $netrules += "-Bypass", "AzureServices"

  if (-not($KVFW_CIDR -eq ""))
  {
    $netrules += "-ipaddressrange", $KVFW_CIDR
  }

  if (-not($subnetid -eq ""))
  {
    $netrules += "-VirtualNetworkResourceId", $subnetid
  }

  $ruleSet = Invoke-Expression "& New-AzKeyVaultNetworkRuleSetObject $netrules"
#endregion kv_firewall_rules

try {
  $newkv = New-AzKeyVault -Name $kvname `
    -Location $location `
    -ResourceGroupName $rgname `
    -EnablePurgeProtection `
    -EnableRbacAuthorization `
    -Sku Standard `
    -networkruleset $ruleSet
}
catch {
  'Failed to create keyvault: ' -f $_.Exception.Message | Write-Error -ErrorAction Stop
  throw
}

if ($appid -ne "")
{
  # grant permissions to SP
  New-AzRoleAssignment -RoleDefinitionName 'Key Vault Secrets User' `
    -ApplicationId $appid `
    -Scope $newkv.ResourceId
}

# grant permission to self for creating the secret
$myupn = (Get-azcontext).account.id
New-AzRoleAssignment -RoleDefinitionName 'Key Vault Administrator' `
  -SignInName $myupn `
  -Scope $newkv.ResourceId

While (-not((get-azroleassignment -scope $newkv.ResourceId | `
  Where-Object {$_.RoleDefinitionName -eq "Key Vault Administrator" -and $_.SignInName -eq $myupn})))
{
  start-sleep -seconds 10
}

# Create secret for rrt
$secretname = "adfsrrt-" + (get-date -Format yyMMdd)
Add-Type -AssemblyName System.Web
$passwd = [System.Web.Security.Membership]::GeneratePassword(32,4)
$secretvalue = ConvertTo-SecureString $passwd -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $kvname -Name $secretname -SecretValue $secretvalue

Write-host "The secret name to use in the script: " $secretname -ForegroundColor Green
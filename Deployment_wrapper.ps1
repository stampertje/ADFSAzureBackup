# Deployment wrapper

$TenantID = "<tenantGUID>"
$subscriptionID = "<subscription GUID>"
$resourceGroup = "<resourcegroupname>"
$location = "westeurope"
$kvName = "<keyvaultname>"
$adfsAzureSubnetId = "/subscriptions/<subscriptionGUID>/resourceGroups/<rgname>/providers/Microsoft.Network/virtualNetworks/<vnetname>/subnets/<subnetname>"
$PublicIp = "123.123.123.123/24" # CIDR notation
$localbackupFolder = "c:\adfsbackup"
$adfssvcacc = "contoso\gmsa_adfs$"

Install-Module AzureAD -force
Foreach ($module in ("Az.KeyVault", "Az.Storage", "Az.Accounts", "Az.Resources")) { Install-Module $module -Force }

Connect-AzureAD -TenantId $TenantID
Connect-AzAccount -TenantID $TenantID
Select-AzSubscription -SubscriptionID $subscriptionID

# Run create service Principal script
$spoutput = .\1_ADFSBackup_CreateServicePrincipal.ps1 -tenantid $TenantID
$appid = $spoutput[0].substring($spoutput.length-36)
$certthumb = $spoutput[1].substring($spoutput.length-40)

# Run create Keyvault script
$KVScript = .\ADFSBackup_CreateKeyVault.ps1 -rgname $resourceGroup `
  -location $location `
  -kvname $kvName `
  -appid $appid `
  -subnetid $adfsAzureSubnetId
$encsecret = $KVScript.substring($KVScript.length-14)

# Run create storage account script
$storageScript = .\3_ADFSBackup_CreateStorageAccount.ps1 -rgname $resourceGroup `
  -location $location `
  -appid $appid `
  -subnetid $adfsAzureSubnetId `
  -SAFW_CIDR $PublicIp
$storageAccount = $storageScript.substring($storageScript.length-20)

.\4_ADFSBackup_CreateSchedule.ps1 -TenantID $TenantID `
  -appid $appid `
  -thumbprint $certthumb `
  -BackupTargetFolder $localbackupFolder `
  -ADFSServiceAccount $adfssvcacc `
  -storageaccount $storageAccount `
  -secretname $encsecret
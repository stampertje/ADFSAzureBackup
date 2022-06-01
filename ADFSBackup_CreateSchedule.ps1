[CmdletBinding()]
param (
    # Parameter help description
    [Parameter(mandatory=$true)]
    [string]
    $TenantID,

    [Parameter(Mandatory=$true)]
    [string]
    $appid,

    [Parameter(Mandatory=$true)]
    [string]
    $thumbprint,

    [Parameter(Mandatory=$true)]
    [string]
    $BackupTargetFolder,

    # ADFS Sercice account is used to access the DKM container in AD.
    # Should be in the format <Domain>\<username> (e.g. contoso\gmsa_adfs$)
    [Parameter(Mandatory=$true)]
    [string]
    $ADFSServiceAccount,

    [Parameter()]
    [int]
    $VersionsToKeep = 1,

    [Parameter(Mandatory=$true)]
    [string]
    $storageaccount,

    [Parameter(mandatory=$true)]
    [string]
    $rgname,

    [Parameter(Mandatory=$true)]
    [string]
    $KeyVault,

    [Parameter(mandatory=$true)]
    [string]
    $secretname
)


#region InstallRRT
# Check if the script is running on the ADFS Primary Farm node
If (-not((Get-ADFSSyncProperties).Role -eq "PrimaryComputer"))
{
    Write-Error -Message "Script is not running on Primary farm node" -ErrorAction Stop
}

# Check if the Rapid Restore Tool is installed. If not download & install.
If (-not(Get-WmiObject win32_product -filter 'Name="ADFS Rapid Recreation Tool"'))
{
    # download the ADFS Rapid Restore Tool
    try {
        Invoke-WebRequest `
        -URI https://download.microsoft.com/download/6/8/A/68AF3CD3-1337-4389-967C-A6751182F286/ADFSRapidRecreationTool.msi `
        -OutFile $env:temp\ADFSRapidRecreationTool.msi
    }
    catch {
        Write-Error -Message "Could not download ADFS Rapid Restore tool" -ErrorAction Stop
    }

    # Install ADFS Rapid Restore Tool
    try {
        $myargs = @(
            "/i",
            "$env:temp\ADFSRapidRecreationTool.msi",
            "/qb",
            "/l*v",
            "$env:temp\ADFSRapidRecreationTool_Install.log"
            )
        Start-Process $env:systemroot\system32\msiexec.exe -wait -ArgumentList $myargs
    }
    catch {
        Write-Error -Message "Could not install ADFS Rapid Restore Tool" -ErrorAction Stop
    }
}
#endregion InstallRRT

#region createlocalbackuppath
if (-not(Test-Path -Path $BackupTargetFolder))
{
  mkdir $BackupTargetFolder
}

#region createlocalbackuppath

#region backupscript
$BackupScript = {
  # ADFS Backup Script

  # Import module 
  try {
      import-module 'C:\Program Files (x86)\ADFS Rapid Recreation Tool\ADFSRapidRecreationTool.dll'
  }
  catch {
      Write-Error -Message "Unable to import ADFS Rapid Restore tool module: " -f $_.exception.message -ErrorAction Stop
  }

  try {
    import-module Az.KeyVault, Az.Storage, Az.Accounts
  }
  catch {
      Write-Error -Message "Unable to import required powershell modules: " -f $_.exception.Message -ErrorAction Stop
  }

  $BackupTargetFolder =  "~TargetFolderPlaceholder~"
  $VersionsToKeep = ~VersionsToKeepPlaceholder~

  $TenantID = "~tenantidplaceholder~"
  $rgname = "~rgnameplaceholder~"
  $storageAccount = "~storageAccountplaceholder~"
  $KeyVault = "~keyvaultplaceholder~"
  $appid = "~appidplaceholder~"
  $thumbprint = "~thumbprintplaceholder~"
  $secretname = "~secretnameplaceholder~"

  
  try {
    Connect-AzAccount -ApplicationId $appid -CertificateThumbprint $thumbprint -TenantId $TenantID
  }
  catch {
    'Failed to connect to Azure: ' -f $_.exception.message | write-error -ErrorAction Stop
  }
  
  $EncryptionPw = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $secretname -AsPlainText

  #region Remove previous versions
  If (-not($Null -eq $VersionsToKeep))
  {
      If((Get-ChildItem $BackupTargetFolder -Directory).count -ge $VersionsToKeep)
      {
          do {
              $OldestBackup = Get-ChildItem $BackupTargetFolder -Directory `
                  | Sort-Object lastwritetime `
                  | Select-Object -First 1
              Remove-Item $OldestBackup.Fullname -Recurse -Force
          } while ((Get-ChildItem -Path $BackupTargetFolder -directory).count -ge $VersionsToKeep)
        }
  }
  #endregion Remove previous versions

  #region ExecuteBackup
  $init = {import-module 'C:\Program Files (x86)\ADFS Rapid Recreation Tool\ADFSRapidRecreationTool.dll'}
  
  $BackupArgs = @(
    "FileSystem"
    $BackupTargetFolder
    $EncryptionPw)

  $BackupJob = Start-Job {Backup-ADFS -StorageType $args[0] -StoragePath $args[1] -EncryptionPassword $args[2] -BackupDKM} `
    -ArgumentList $BackupArgs `
    -InitializationScript $init
  
  Wait-Job $BackupJob
  Receive-Job $BackupJob
  #endregion ExecuteBackup

  #region UploadToStorageAccount
  $storageAccountObject = Get-AzStorageAccount -ResourceGroupName $rgname -Name $storageaccount
  $storageContext = $storageAccountObject.Context

  $ContainerName = 'adfsbackup'
  if ($null -eq (Get-azstoragecontainer -name $containername -context $storageContext -ErrorAction SilentlyContinue))
  {
    New-AzStorageContainer -Name $ContainerName -Context $storageContext -Permission Blob
  }

  $NewestBackup = Get-ChildItem $BackupTargetFolder -Directory `
    | Sort-Object lastwritetime -Descending `
    | Select-Object -First 1

  Foreach ($file in (Get-ChildItem $NewestBackup.fullname))
  {
    try {
      Set-AzStorageBlobContent `
        -Context $storageContext `
        -Container $ContainerName `
        -File $file.fullname `
        -Blob $file.Name `
        -force
    }
    catch {
      'failed to upload file: ' -f $_exception.message | write-error -erroraction Stop
    }

  }
  #endregion UploadToStorageAccount
}
#endregion backupscript


#region write backupscript to disk
If (Test-Path $BackupTargetFolder\ADFSBackup.ps1)
{
    Remove-Item $BackupTargetFolder\ADFSBackup.ps1 -Force
}

$BackupScript = $BackupScript.ToString().replace("~TargetFolderPlaceholder~",$BackupTargetFolder)
$BackupScript = $BackupScript.ToString().replace("~VersionsToKeepPlaceholder~",$VersionsToKeep)
$BackupScript = $BackupScript.ToString().replace("~rgnameplaceholder~",$rgname)
$BackupScript = $BackupScript.ToString().replace("~storageAccountplaceholder~",$storageAccount)
$BackupScript = $BackupScript.ToString().replace("~keyvaultplaceholder~",$KeyVault)
$BackupScript = $BackupScript.ToString().replace("~tenantidplaceholder~",$TenantID)
$BackupScript = $BackupScript.ToString().replace("~appidplaceholder~",$appid)
$BackupScript = $BackupScript.ToString().replace("~thumbprintplaceholder~",$thumbprint)
$BackupScript = $BackupScript.ToString().replace("~secretnameplaceholder~",$secretname)

$BackupScript | Out-file -FilePath $BackupTargetFolder\ADFSBackup.ps1 -Force
#endregion write backupscript to disk

#region create scheduled task
If ($null -eq $ScheduledTaskName)
{
    $ScheduledTaskName = "ADFS RRT Azure Backup"
}

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
    -Argument $BackupTargetFolder\ADFSBackup.ps1
$trigger =  New-ScheduledTaskTrigger -Daily -At 1am

$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType Password -UserId $ADFSServiceAccount

If (Get-ScheduledTask | Where-Object {$_.URI -ilike "*$ScheduledTaskName*"})
{

    Set-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -TaskName $ScheduledTaskName `
        -Principal $TaskPrincipal

} else {

    Register-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -TaskName $ScheduledTaskName `
        -Description "ADFS RRT Azure Backup" `
        -Principal $TaskPrincipal
}
#endregion create scheduled task

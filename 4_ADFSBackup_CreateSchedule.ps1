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
  try {
    $storageAccountObject = Get-AzStorageAccount -ResourceGroupName $rgname -Name $storageaccount
    $storageContext = $storageAccountObject.Context      
  }
  catch {
    'Failed to get storage context for upload: ' -f $_.exception.message | write-error -ErrorAction Stop
    throw
  }
  
  $NewestBackup = Get-ChildItem $BackupTargetFolder -Directory `
    | Sort-Object lastwritetime -Descending `
    | Select-Object -First 1

  $ContainerName = $NewestBackup.Name.replace("_","-").ToLower()

  if ($null -eq (Get-azstoragecontainer -name $containername -context $storageContext -ErrorAction SilentlyContinue))
  {
    try {
      New-AzStorageContainer -Name $ContainerName -Context $storageContext
    }
    catch {
      'Failed to create container in storage account: ' -f $_.exception.message | write-error -ErrorAction Stop
      throw
    }
  }

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
      throw
    }

    if (-not($null -eq $versionsToKeep))
    {
      # Clean up old backups
      $ExistingBackups = Get-azstoragecontainer -Context $storageContext | sort-object LastModified
      If ($ExistingBackups.count -gt $VersionsToKeep)
      { 
        $containersToDelete = ($ExistingBackups.count - $versionsToKeep)

        For ($i=0;$i -lt $containersToDelete;$i++)
        {
          try {
            Remove-AzStorageContainer -name $ExistingBackups[$i].Name -Context $storageContext -Force
          }
          catch {
            'Failed to delete container: ' -f $_.exception.message | write-error
          }
        }
      }
    }
  }
  #endregion UploadToStorageAccount
}
#endregion backupscript


#region write backupscript to disk
If (Test-Path $BackupTargetFolder\ADFSBackup.ps1)
{
  $now = get-date -format yyyyMMddhhmm
  $newfilename = "ADFSBackup_" + $now + ".bak"
  Move-Item -Path $BackupTargetFolder\ADFSBackup.ps1 -Destination $BackupTargetFolder\$newfilename  
  #Remove-Item $BackupTargetFolder\ADFSBackup.ps1 -Force
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

$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType Password -UserId $ADFSServiceAccount -RunLevel Highest

$TaskProperties = @{
  Action = $action
  Trigger = $trigger
  TaskName = $ScheduledTaskName
}

if (-not($ADFSServiceAccount -like "*$")) # If not a GMSA
{
  $SecurePassword = Read-host "Please enter service account password: " -AsSecureString
  # Task creation expect standard string
  $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
  $svcaccpassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

  $TaskProperties += @{
    user = $ADFSServiceAccount
    password = $svcaccpassword
  }
} else {
  $TaskProperties += @{
    Principal = $TaskPrincipal
  }
}

If (Get-ScheduledTask | Where-Object {$_.URI -ilike "*$ScheduledTaskName*"})
{
  try {
    Set-ScheduledTask @TaskProperties
  }
  catch {
    'Failed to update existing scheduled task: ' -f $_.exception.message | write-error
    throw
  }
    
} else {
  try {
    $TaskProperties += @{Description="ADFS RRT Azure Backup"}
    Register-ScheduledTask @TaskProperties
  }
  catch {
    'Failed to register new scheduled task: ' -f $_.exception.message | write-error
    throw
  }
}
#endregion create scheduled task

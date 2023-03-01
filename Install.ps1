#Requires -RunAsAdministrator

param (
    [string] $InstallationFiles = $null,
    [string] $InstallDirectory = "C:\Program Files\DownloadBlocker",
    [switch] $Chrome,
    [switch] $Edge,
    [Parameter()] [Alias("H")] [Switch] $Help
 )

 function AddManifestToRegistry{
    param (
        [Parameter(Mandatory)] [string] $RegistryPath,
        [Parameter(Mandatory)] [string] $ManifestPath
    )
    
    try{
        New-Item $RegistryPath -Name "securityjosh.download_blocker" -Force | Out-Null
        Set-ItemProperty -Path "$RegistryPath\securityjosh.download_blocker" -Name "(Default)" -Value $ManifestPath -Force
        Write-Host "[*] Installed Manifest for key '$RegistryPath\securityjosh.download_blocker'"
    }catch{
        Write-Host "[!] Failed to set value for '$RegistryPath\securityjosh.download_blocker'"
    }
 }

 if($Help -or (!$Chrome -and !$Edge)){
    Write-Output "$(split-path $MyInvocation.InvocationName -Leaf) [https://github.com/SecurityJosh/DownloadBlockerNativeMessagingHost]`nUsage:`n`t-h, -help `t`t`t`tDisplays this help message`n`t-InstallationFiles <File Path>`t`tRuns the installer with a local copy of the installation files. If omitted, the latest version is downloaded from GitHub.`n`t-InstallDirectory <Folder Path>`t`tThe installation directory. If omitted, defaults to C:\Program Files\DownloadBlocker`n`t-Chrome`t`t`t`t`tInstalls the Native Messaging Host for the Chrome Browser`n`t-Edge`t`t`t`t`tInstalls the Native Messaging Host for the Microsoft Edge Browser`n`tNote: At least one of -Chrome, -Edge are required"
    return;
 }

 # Make sure that the install directory exists / we can create it

if (!(Test-Path -PathType Container -Path $InstallDirectory)){
    $InstallationFolder = New-Item -ItemType Directory -Force -Path $InstallDirectory -ErrorAction SilentlyContinue
    
    if(!$InstallationFolder){
        Write-Host "[!] Could not create the installation folder"
        return;
    }
}

# Download the NativeMessagingHost if the -InstallationFiles parameter is not specified

if(!$InstallationFiles){
    try{
        $LatestArchiveUrl = (Invoke-WebRequest "https://api.github.com/repos/SecurityJosh/DownloadBlockerNativeMessagingHost/releases/latest" | ConvertFrom-Json).assets.browser_download_url
        $InstallationFiles = (New-TemporaryFile  | ForEach-Object  {$_ | Rename-Item -NewName "$($_.BaseName).zip" -PassThru}).FullName
        Invoke-WebRequest $LatestArchiveUrl -OutFile $InstallationFiles
        Write-Host "[*] Downloaded installation files to '$InstallationFiles'"
    }catch{
        Write-Host "[!] Failed to download installation files"
        return;
    }    
}

 # Make sure that $InstallationFiles exists

 if(!(Test-Path -PathType Leaf -Path $InstallationFiles)){
    Write-Host "[!] Could not find installation files"
    return;
 }

 # Extract the files into the install folder

 try{
    Expand-Archive -Path $InstallationFiles -DestinationPath $InstallDirectory -Force
    Write-Host "[*] File extraction completed successfully"
 }catch{
    Write-Host "[!] File extraction failed"
    return;
 }

 # Create the NativeMessagingHost manifest file

 $Manifest = [ordered]@{
  name = "securityjosh.download_blocker";
  description = "Native Helper for Download Blocker";
  path = ($InstallDirectory + "\" + "DownloadBlockerNativeMessagingHost.exe");
  type ="stdio";
  allowed_origins = @("chrome-extension://lpolaoejidbgebbkpphcpmocjkpgopak/", "chrome-extension://kippogcnigegkjidkpfpaeimabcoboak/")
} | ConvertTo-Json

$ManifestPath = ($InstallDirectory + "\" + "Manifest.json")

try{
    $Manifest | Out-File -FilePath $ManifestPath -Force -Encoding ascii
    Write-Host "[*] Created manifest file '$ManifestPath'"
}catch{
    Write-Host "[!] Failed to create manifest file '$ManifestPath'"
}

# Point the correct registry keys to the manifest file

if($Chrome){
    AddManifestToRegistry -RegistryPath "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts" -ManifestPath $ManifestPath
}

if($Edge){
    AddManifestToRegistry -RegistryPath "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts" -ManifestPath $ManifestPath
}

try{
    if((Get-Item -Path ($InstallationFiles)).DirectoryName -eq $env:TEMP){
        Remove-Item -Path $InstallationFiles -ErrorAction Stop
        Write-Host "[*] Removed temporary installation file '$InstallationFiles'"
    }else{
        Write-Host "[*] Not removing user-supplied installation file"
    }
}catch{
    Write-Host "[!] Failed to remove temporary installation file '$InstallationFiles'"
}
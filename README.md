# Download Blocker Native Messaging Host

This Native Messaging Host is an optional addition to the [Download Blocker](https://github.com/SecurityJosh/DownloadBlocker) chromium extension. It calculates downloaded file metadata on behalf of the extension, and is only invoked when the extension is unable to calculate this metadata itself.

## Metadata Calculated

The Native Messaging Host calculates the same metadata as the extension itself:

* File SHA256
* If the file contains office macros
* The list of filenames inside a .zip archive.

The metadata calculated by the Native Messaging Host is only sent to the Download Blocker extension.

## When is it invoked?

As mentioned above, the Native Messaging Host is only invoked when the extension itself has been unable to calculate the downloaded file's metadata. This is generally due to the extension's content script not being injected. Examples of when this might be the case include:
* HTML Smuggled downloads where the initiating resource is a local file (e.g. a .html email attachment), when "Allow access to file URLs" has not been enabled.
* Non-Smuggled downloads
* HTML Smuggled downloads where a browser or extension bug prevents content-script injection. (e.g. https://bugs.chromium.org/p/chromium/issues/detail?id=1393521)

## Installation

    Install.ps1 [https://github.com/SecurityJosh/DownloadBlockerNativeMessagingHost]
    Usage:
        -h, -help                           Displays this help message
        -InstallationFiles <File Path>      Runs the installer with a local copy of the installation files. If omitted, the latest version is download from GitHub.
        -InstallDirectory <Folder Path>     The installation directory. If omitted, defaults to C:\Program Files\DownloadBlocker
        -Chrome                             Installs the Native Messaging Host for the Chrome Browser
        -Edge                               Installs the Native Messaging Host for the Microsoft Edge Browser
        Note: At least one of -Chrome, -Edge are required

## Example (Download install files from GitHub, keep the default installation directory, install for Chrome and Edge)
    .\Install.ps1 -Chrome -Edge

## Example (Local installation, keep the default installation directory, install for Chrome and Edge)
    # Download the installation files from https://github.com/SecurityJosh/DownloadBlockerNativeMessagingHost/releases
    .\Install.ps1 -InstallationFiles "DownloadBlockerNativeMessagingHost_1.0.0.zip" -Chrome -Edge
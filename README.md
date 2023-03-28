# PSADT.RunAsActiveUser
Extension for PowerShell App Deployment Toolkit that executes processes or scriptblocks as the active user under SYSTEM context.

## Features
- Executes processes, scripts or scriptblocks as the active user in SYSTEM context.
- No need to change scripts, wraps original **Execute-ProcessAsUser** function but without UserName selection.
- If executed under USER context, the function uses **Execute-Process**, no interpersonate needed.
- No need to save scripts or to create files executed by scheduled tasks.
- Functions tested under SCCM, Intune and normal Scheduled Task.
- Executes scriptblocks on the fly if less than 32 KBytes (Windows 10), 8 KBytes (Windows 8.0 and under).
- If size exceed the maximum, the temporary script is saved encrypted by 32 KB key and deleted during execution.
- The execution of interpersonated processes returns the standard output of the invoked processes.
- Able to Wait if neccesary.
- Execution privilege works like original **Execute-ProcessAsUser** function, if active user is administrator, the process can be elevated.
- Able to hide windows or console applications using parameters.
- Fallbacks to original **Execute-ProcessAsUser** if any error occurs.
- *ContinueOnError* and *ExitScriptOnError* support.

## Disclaimer
```diff
- Test the functions before production.
- Make a backup before applying.
- Check the config file options description.
- Run AppDeployToolkitHelp.ps1 for more help and parameter descriptions.
```

## Functions
`Functions are based on existing 3rd party functions, see external links`
* **Invoke-ProcessAsActiveUser** - Executes a process with the active logged in user account, to provide interaction with user in the SYSTEM context.
* **Remove-Comments** - Strips comments and extra whitespace from a script.

## Usage
```PowerShell
# Creates a ScriptBlock with commands
$ScriptBlockExample = {
  return $env:USERNAME
}

# Executes the ScriptBlock as active user under SYSTEM context
Invoke-ProcessAsActiveUser -ScriptBlock $ScriptBlockExample -CaptureOutput -Wait
```

## Internal functions
`This set of functions are internals and are not designed to be called directly`
* **New-DynamicFunction** - Defines a new function with the given name, scope and content given.

## Extension Exit Codes
|Exit Code|Function|Exit Code Detail|
|:----------:|:--------------------|:-|
|70601|Invoke-ProcessAsActiveUser|Microsoft PowerShell doesn't seem to be installed.|
|70602|Invoke-ProcessAsActiveUser|The script file could not be found.|
|70603|Invoke-ProcessAsActiveUser|An error occured when trying to save encrypted ScriptBlock to temp folder.|
|70604|Invoke-ProcessAsActiveUser|Not running with correct privilege. You must run this script as system or have the 'SeDelegateSessionUserImpersonatePrivilege' token.|
|70605|Invoke-ProcessAsActiveUser|Failed to execute process as currently logged on user.|
|70606|Remove-Comments|Error ocurred when reading source file/scriptblock.|
|70607|Remove-Comments|Error ocurred when removing comments from source file/scriptblock.|

## How to Install
#### 1. Download and extract into Toolkit folder.
#### 2. Edit *AppDeployToolkitExtensions.ps1* file and add the following lines.
#### 3. Create an empty array (only once if multiple extensions):
```PowerShell
## Variables: Extensions to load
$ExtensionToLoad = @()
```
#### 4. Add Extension Path and Script filename (repeat for multiple extensions):
```PowerShell
$ExtensionToLoad += [PSCustomObject]@{
	Path   = "PSADT.RunAsActiveUser"
	Script = "RunAsActiveUserExtension.ps1"
}
```
#### 5. Complete with the remaining code to load the extension (only once if multiple extensions):
```PowerShell
## Loading extensions
foreach ($Extension in $ExtensionToLoad) {
	$ExtensionPath = $null
	if ($Extension.Path) {
		[IO.FileInfo]$ExtensionPath = Join-Path -Path $scriptRoot -ChildPath $Extension.Path | Join-Path -ChildPath $Extension.Script
	}
	else {
		[IO.FileInfo]$ExtensionPath = Join-Path -Path $scriptRoot -ChildPath $Extension.Script
	}
	if ($ExtensionPath.Exists) {
		try {
			. $ExtensionPath
		}
		catch {
			Write-Log -Message "An error occurred while trying to load the extension file [$($ExtensionPath)].`r`n$(Resolve-Error)" -Severity 3 -Source $appDeployToolkitExtName
		}
	}
	else {
		Write-Log -Message "Unable to locate the extension file [$($ExtensionPath)]." -Severity 2 -Source $appDeployToolkitExtName
	}
}
```

## Requirements
* Powershell 5.1+
* PSAppDeployToolkit 3.8.4+

## External Links
* [PowerShell App Deployment Toolkit](https://psappdeploytoolkit.com/)
* [KelvinTegelaar/RunAsUser: a PowerShell module that allows you to impersonate the currently logged on user, while running PowerShell.exe as system.](https://github.com/KelvinTegelaar/RunAsUser)
* [PowerShellMafia/PowerSploit: PowerSploit - A PowerShell Post-Exploitation Framework](https://github.com/PowerShellMafia/PowerSploit/)

<#
.SYNOPSIS
	Run As Active User Extension script file, must be dot-sourced by the AppDeployToolkitExtension.ps1 script.
.DESCRIPTION
	Execute processes as the active user if the privileges are adecuated or execute in user context if apply.
.NOTES
	Extension Exit Codes:
	70601: Invoke-ProcessAsActiveUser - Microsoft PowerShell doesn't seem to be installed.
	70602: Invoke-ProcessAsActiveUser - The script file could not be found.
	70603: Invoke-ProcessAsActiveUser - An error occured when trying to save encrypted ScriptBlock to temp folder.
	70604: Invoke-ProcessAsActiveUser - Not running with correct privilege. You must run this script as system or have the 'SeDelegateSessionUserImpersonatePrivilege' token.
	70605: Invoke-ProcessAsActiveUser - Failed to execute process as currently logged on user.
	70606: Remove-Comments - Error ocurred when reading source file/scriptblock.
	70607: Remove-Comments - Error ocurred when removing comments from source file/scriptblock.

	Author:  Leonardo Franco Maragna
	Version: 1.0.1
	Date:    2023/04/14
#>
[CmdletBinding()]
Param (
)

##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

## Variables: Extension Info
$RunAsActiveUserExtName = "RunAsActiveUserExtension"
$RunAsActiveUserExtScriptFriendlyName = "Run As Active User Extension"
$RunAsActiveUserExtScriptVersion = "1.0.1"
$RunAsActiveUserExtScriptDate = "2023/04/14"
$RunAsActiveUserExtSubfolder = "PSADT.RunAsActiveUser"
$RunAsActiveUserExtCustomTypesName = "RunAsActiveUserExtension.cs"
$RunAsActiveUserExtConfigFileName = "RunAsActiveUserConfig.xml"

## Variables: Run As Active User Script Dependency Files
[IO.FileInfo]$dirRunAsActiveUserExtFiles = Join-Path -Path $scriptRoot -ChildPath $RunAsActiveUserExtSubfolder
[IO.FileInfo]$RunAsActiveUserConfigFile = Join-Path -Path $dirRunAsActiveUserExtFiles -ChildPath $RunAsActiveUserExtConfigFileName
[IO.FileInfo]$RunAsActiveUserCustomTypesSourceCode = Join-Path -Path $dirRunAsActiveUserExtFiles -ChildPath $RunAsActiveUserExtCustomTypesName
if (-not $RunAsActiveUserConfigFile.Exists) { throw "$($RunAsActiveUserExtScriptFriendlyName) XML configuration file [$RunAsActiveUserConfigFile] not found." }
if (-not $RunAsActiveUserCustomTypesSourceCode.Exists) { throw "$($RunAsActiveUserExtScriptFriendlyName) custom types source code file [$RunAsActiveUserCustomTypesSourceCode] not found." }

## Import variables from XML configuration file
[Xml.XmlDocument]$xmlRunAsActiveUserConfigFile = Get-Content -LiteralPath $RunAsActiveUserConfigFile -Encoding UTF8
[Xml.XmlElement]$xmlRunAsActiveUserConfig = $xmlRunAsActiveUserConfigFile.RunAsActiveUser_Config

#  Get Config File Details
[Xml.XmlElement]$configRunAsActiveUserConfigDetails = $xmlRunAsActiveUserConfig.Config_File

#  Check compatibility version
$configRunAsActiveUserConfigVersion = [string]$configRunAsActiveUserConfigDetails.Config_Version
#$configRunAsActiveUserConfigDate = [string]$configRunAsActiveUserConfigDetails.Config_Date

try {
	if ([version]$RunAsActiveUserExtScriptVersion -ne [version]$configRunAsActiveUserConfigVersion) {
		Write-Log -Message "The $($RunAsActiveUserExtScriptFriendlyName) version [$([version]$RunAsActiveUserExtScriptVersion)] is not the same as the $($RunAsActiveUserExtConfigFileName) version [$([version]$configRunAsActiveUserConfigVersion)]. Problems may occurs." -Severity 2 -Source ${CmdletName}
	}
}
catch {}

#  Get Run As Active User General Options
[Xml.XmlElement]$xmlRunAsActiveUserOptions = $xmlRunAsActiveUserConfig.RunAsActiveUser_Options
$configRunAsActiveUserGeneralOptions = [PSCustomObject]@{
	ReplaceOriginalExecuteProcessAsUser = Invoke-Expression -Command 'try { [boolean]::Parse([string]($xmlRunAsActiveUserOptions.ReplaceOriginalExecuteProcessAsUser)) } catch { $false }'
	FallbackToOriginalFunctionOnError   = Invoke-Expression -Command 'try { [boolean]::Parse([string]($xmlRunAsActiveUserOptions.FallbackToOriginalFunctionOnError)) } catch { $false }'
}

#  Defines the original functions to be renamed
$FunctionsToRename = @()
$FunctionsToRename += [PSCustomObject]@{
	Scope = "Script"
	Name  = "Execute-ProcessAsUserOriginal"
	Value = $(${Function:Execute-ProcessAsUser}.ToString() -replace "http(s){0,1}:\/\/psappdeploytoolkit\.com", "")
}

#endregion
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings

#region Function New-DynamicFunction
Function New-DynamicFunction {
	<#
	.SYNOPSIS
		Defines a new function with the given name, scope and content given.
	.DESCRIPTION
		Defines a new function with the given name, scope and content given.
	.PARAMETER Name
		Function name.
	.PARAMETER Scope
		Scope where the function will be created.
	.PARAMETER Value
		Logic of the function.
	.PARAMETER ContinueOnError
		Continue if an error occured while trying to create new function. Default: $false.
	.INPUTS
		None
		You cannot pipe objects to this function.
	.OUTPUTS
		None
		This function does not generate any output.
	.EXAMPLE
		New-DynamicFunction -Name 'Exit-ScriptOriginal' -Scope 'Script' -Value ${Function:Exit-Script}
	.NOTES
		This is an internal script function and should typically not be called directly.
		Author: Leonardo Franco Maragna
		Part of Run As Active User Extension
	.LINK
		https://github.com/LFM8787/PSADT.RunAsActiveUser
		https://psappdeploytoolkit.com
		http://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[string]$Name,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[ValidateSet("Global", "Local", "Script")]
		[string]$Scope,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[string]$Value,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $false
	)

	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		try {
			$null = New-Item -Path function: -Name "$($Scope):$($Name)" -Value $Value -Force

			if ($?) {
				Write-Log -Message "Successfully created function [$Name] in scope [$Scope]." -Source ${CmdletName} -DebugMessage
			}
		}
		catch {
			Write-Log -Message "Failed when trying to create new function [$Name] in scope [$Scope].`r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			if (-not $ContinueOnError) {
				throw "Failed when trying to create new function [$Name] in scope [$Scope]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Invoke-ProcessAsActiveUser
Function Invoke-ProcessAsActiveUser {
	<#
	.SYNOPSIS
		Executes a process with the active logged in user account, to provide interaction with user in the SYSTEM context.
	.DESCRIPTION
		Executes a process with the active logged in user account, to provide interaction with user in the SYSTEM context.
		When the context is user (not SYSTEM) the function executes the logic in that context, no invokation as user required.
	.PARAMETER UserName
		Logged in Username under which to run the process from. Only used when falling back to original function. Default is: The active console user. if no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.
	.PARAMETER Path
		Path to the file being executed.
	.PARAMETER ArgumentList
		Arguments to be passed to the file being executed. Parameters alias for backward compatibility.
	.PARAMETER SecureArgumentList
		Hides all parameters passed to the executable from the Toolkit log file. SecureParameters alias for backward compatibility.
	.PARAMETER ScriptPath
		Path to a PowerShell script to be executed.
	.PARAMETER ScriptBlock
		ScriptBlock to be executed.
	.PARAMETER TempPath
		Path to the temporary directory used to store the script to be executed as user. if using a user writable directory, ensure you select -RunLevel "LeastPrivilege".
	.PARAMETER RemoveScriptBlockComments
		Calls the Remove-Comments function to reduce the scriptblock size. Default is $true.
	.PARAMETER UseWindowsPowerShell
		Try to execute the powershell script or scriptblock using Windows PowerShell.
	.PARAMETER UseMicrosoftPowerShell
		Try to execute the powershell script or scriptblock using Microsoft PowerShell if installed.
	.PARAMETER Wait
		Wait for the process to complete execution before accepting more input. Default is $false.
	.PARAMETER ShowWindow
		Show the PowerShell console or the Path executable given window.
	.PARAMETER RunLevel
		Specifies the level of user rights to run the process. The acceptable values for this parameter are:
		- HighestAvailable: Processes run by using the highest available privileges (Admin privileges for Administrators). Default Value.
		- LeastPrivilege: Processes run by using the least-privileged user account (LUA) privileges.
	.PARAMETER CaptureOutput
		Returns a string with the standard output from the execution. Only if Wait is also specified. PassThru alias for backward compatibility.
	.PARAMETER ExitOnProcessFailure
		Specifies whether the function should call Exit-Script when the process returns an exit code that is considered an error/failure. Default: $true
	.PARAMETER ContinueOnError
		Continue if an error occurred while trying to start the process. Default: $false.
	.PARAMETER FallbackToOriginalFunctionOnError
		If ContinueOnError and any error occurs, fallback to original Execute-ProcessAsUser function.
	.PARAMETER DisableFunctionLogging
		Disables function logging
	.INPUTS
		None
		You cannot pipe objects to this function.
	.OUTPUTS
		System.String
		Returns the standard output of the executed process or the exit code.
	.EXAMPLE
		Invoke-ProcessAsActiveUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
		Execute process under the active user account detected.
	.NOTES
		Based on the work of RunAsUser Module from Kelvin Tegelaar
		Distributed under MIT License
		Author: Leonardo Franco Maragna
		Part of Run As Active User Extension
	.LINK
		https://github.com/LFM8787/PSADT.RunAsActiveUser
		https://github.com/KelvinTegelaar/RunAsUser
		https://psappdeploytoolkit.com
		http://psappdeploytoolkit.com
	#>
	[CmdletBinding(DefaultParameterSetName = "FilePath")]
	Param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[string]$UserName = $RunAsActiveUser.NTAccount,
		[Parameter(Mandatory = $true, ParameterSetName = "FilePath")]
		[ValidateNotNullOrEmpty()]
		[IO.FileInfo]$Path,
		[Parameter(Mandatory = $false, ParameterSetName = "FilePath")]
		[Parameter(Mandatory = $false, ParameterSetName = "ScriptPath")]
		[Alias("Parameters")]
		[string]$ArgumentList,
		[Parameter(ParameterSetName = "FilePath")]
		[Parameter(ParameterSetName = "ScriptPath")]
		[Alias("SecureParameters")]
		[switch]$SecureArgumentList,
		[Parameter(Mandatory = $true, ParameterSetName = "ScriptPath")]
		[ValidateNotNullOrEmpty()]
		[IO.FileInfo]$ScriptPath,
		[Parameter(Mandatory = $true, ParameterSetName = "ScriptBlock")]
		[ValidateNotNullOrEmpty()]
		[scriptblock]$ScriptBlock,
		[Parameter(Mandatory = $false, ParameterSetName = "ScriptBlock")]
		[ValidateNotNullorEmpty()]
		[string]$TempPath = $loggedOnUserTempPath,
		[Parameter(ParameterSetName = "ScriptBlock")]
		[boolean]$RemoveScriptBlockComments = $true,
		[Parameter(ParameterSetName = "ScriptBlock")]
		[Parameter(ParameterSetName = "ScriptPath")]
		[switch]$UseWindowsPowerShell,
		[Parameter(ParameterSetName = "ScriptBlock")]
		[Parameter(ParameterSetName = "ScriptPath")]
		[switch]$UseMicrosoftPowerShell,
		[Parameter(Mandatory = $false)]
		[IO.FileInfo]$WorkingDirectory,
		[switch]$Wait,
		[switch]$ShowWindow,
		[Parameter(Mandatory = $false)]
		[ValidateSet("HighestAvailable", "LeastPrivilege")]
		[string]$RunLevel = "HighestAvailable",
		[Alias("PassThru")]
		[switch]$CaptureOutput,
		[boolean]$ExitOnProcessFailure = $true,
		[boolean]$ContinueOnError = $false,
		[boolean]$FallbackToOriginalFunctionOnError = $configRunAsActiveUserGeneralOptions.FallbackToOriginalFunctionOnError,
		[switch]$DisableFunctionLogging
	)

	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		if ($SecureArgumentList) { $PSBoundParameters.Remove("ArgumentList") }
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		## Force function logging if debugging
		if ($configToolkitLogDebugMessage) { $DisableFunctionLogging = $false }
	}
	Process {
		#region Function reusable ScriptBlocks
		## Defines the PowerShell executable to use
		[scriptblock]$DefinePowerShellPath = {
			$CurrentProcessPath = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Path

			if ($UseMicrosoftPowerShell) {
				[IO.FileInfo]$Path = (Get-ChildItem -Path "$($envProgramFiles)*\PowerShell\*" -Recurse -Include "pwsh.exe").FullName | Select-Object -First 1
				if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
					Write-Log -Message "Microsoft PowerShell doesn't seem to be installed." -Severity 3 -Source ${CmdletName}
					if (-not $ContinueOnError) {
						if ($ExitOnProcessFailure) {
							Exit-Script -ExitCode 70601
						}
						throw "Microsoft PowerShell doesn't seem to be installed."
					}
				}
				$UseMicrosoftPowerShell = $false
			}
			if ($UseWindowsPowerShell -or ($CurrentProcessPath -like "*powershell_ise*")) {
				[IO.FileInfo]$Path = "$($envSystem32Directory)\WindowsPowerShell\v1.0\powershell.exe"
			}
			elseif (-not $UseMicrosoftPowerShell) {
				[IO.FileInfo]$Path = $CurrentProcessPath
			}
		}

		## Fallbacks to original function if any problem occur
		[scriptblock]$FallbackToOriginalFunction = {
			#  Adapts the function parameters to fit the original one
			$ExecuteProcessAsUserParameters = @{}
			$ExecuteProcessAsUserParameters.Add("UserName", $UserName)
			$ExecuteProcessAsUserParameters.Add("Path", $Path)
			if (-not [string]::IsNullOrEmpty($TempPath)) {
				$ExecuteProcessAsUserParameters.Add("TempPath", $TempPath)
			}
			if (-not [string]::IsNullOrEmpty($ArgumentList)) {
				$ExecuteProcessAsUserParameters.Add("Parameters", $ArgumentList)
			}
			$ExecuteProcessAsUserParameters.Add("SecureParameters", $SecureArgumentList)
			$ExecuteProcessAsUserParameters.Add("RunLevel", $RunLevel)
			$ExecuteProcessAsUserParameters.Add("Wait", $Wait)
			$ExecuteProcessAsUserParameters.Add("PassThru", $CaptureOutput)
			$ExecuteProcessAsUserParameters.Add("WorkingDirectory", $WorkingDirectory)
			$ExecuteProcessAsUserParameters.Add("ContinueOnError", $ContinueOnError)

			if ($CaptureOutput) {
				Write-Log -Message "When falling back to original 'Execute-ProcessAsUser' function, the CaptureOutput parameter only returns the exit code." -Severity 2 -Source ${CmdletName}
			}

			#  Calls the original function with the given parameters
			if ($configRunAsActiveUserGeneralOptions.ReplaceOriginalExecuteProcessAsUser) {
				$Return = Execute-ProcessAsUserOriginal @ExecuteProcessAsUserParameters
			}
			else {
				$Return = Execute-ProcessAsUser @ExecuteProcessAsUserParameters
			}			

			if ($CaptureOutput) {
				return $Return
			}
		}
		#endregion


		if ($PSCmdlet.ParameterSetName -eq "FilePath") {
			## Validate and find the fully qualified path for the $Path variable.
			if (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
				if (-not ($DisableFunctionLogging)) { Write-Log -Message "[$Path] is a valid fully qualified path, continue." -Source ${CmdletName} }
				if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
					Write-Log -Message "File [$Path] not found." -Severity 3 -Source ${CmdletName}
					if (-not $ContinueOnError) {
						throw "File [$Path] not found."
					}
					return
				}
			}
			else {
				#  The first directory to search will be the 'Files' subdirectory of the script directory
				[String]$PathFolders = $dirFiles
				#  Add the current location of the console (Windows always searches this location first)
				[String]$PathFolders = $PathFolders + ";" + (Get-Location -PSProvider "FileSystem").Path
				#  Add the new path locations to the PATH environment variable
				$env:PATH = $PathFolders + ";" + $env:PATH

				#  Get the fully qualified path for the file. Get-Command searches PATH environment variable to find this value.
				[String]$FullyQualifiedPath = Get-Command -Name $Path -CommandType "Application" -TotalCount 1 -Syntax -ErrorAction "Stop"

				#  Revert the PATH environment variable to it's original value
				$env:PATH = $env:PATH -replace [RegEx]::Escape($PathFolders + ";"), ""

				if ($FullyQualifiedPath) {
					if (-not ($DisableFunctionLogging)) { Write-Log -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]." -Source ${CmdletName} }
					[IO.FileInfo]$Path = $FullyQualifiedPath
				}
				else {
					Write-Log -Message "[$Path] contains an invalid path or file name." -Severity 3 -Source ${CmdletName}
					if (-not $ContinueOnError) {
						throw "[$Path] contains an invalid path or file name."
					}
					return
				}
			}
		}
		
		if ($PSCmdlet.ParameterSetName -eq "ScriptPath") {
			## Defines the PowerShell executable to use
			Invoke-Command -ScriptBlock $DefinePowerShellPath -NoNewScope

			if (Test-Path -LiteralPath $ScriptPath -PathType Leaf -ErrorAction SilentlyContinue) {
				## Defines ScriptPath ArgumentList parameter
				if ([string]::IsNullOrEmpty($ArgumentList)) {
					$ArgumentList = "-ExecutionPolicy Bypass -Window Normal -File `"$($ScriptPath)`""
				}
				else {
					$ArgumentList = "-ExecutionPolicy Bypass -Window Normal -File `"$($ScriptPath)`" $ArgumentList"
				}	
			}
			else {
				Write-Log -Message "The script file [$ScriptPath] could not be found." -Severity 3 -Source ${CmdletName}
				if (-not $ContinueOnError) {
					if ($ExitOnProcessFailure) {
						Exit-Script -ExitCode 70602
					}
					throw "The script file [$ScriptPath] could not be found."
				}
				return
			}
		}

		if ($PSCmdlet.ParameterSetName -eq "ScriptBlock") {
			## Defines the PowerShell executable to use
			Invoke-Command -ScriptBlock $DefinePowerShellPath -NoNewScope

			## Defines maximum encoded command length
			if ([Version]::new([int32]$envOSVersionMajor, [int32]$envOSVersionMinor) -lt [Version]::new(6, 2)) {
				$EncodedArgumentListMaximumLength = 8190
			}
			else {
				$EncodedArgumentListMaximumLength = 32760 # MAX_PATH defined to 32 KBytes
			}

			## Removes ScriptBlock comments to reduce length
			if ($RemoveScriptBlockComments) {
				$ScriptBlock = Remove-Comments -ScriptBlock $ScriptBlock -ExitOnProcessFailure $ExitOnProcessFailure -ContinueOnError $ContinueOnError
			}

			## Defines encoded ArgumentList
			$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
			$EncodedArgumentList = "-ExecutionPolicy Bypass -Window Normal -EncodedCommand $($EncodedCommand)"

			## Checks if the encoded command length is too long and needs to be saved as script
			if ((($Path.FullName).Length + $EncodedArgumentList.Length) -gt $EncodedArgumentListMaximumLength) {
				try {
					## Save encrypted content	
					#  Define temp file
					$TempContentGuid = New-Guid
					[IO.FileInfo]$TempContentPath = Join-Path -Path $TempPath -ChildPath "$($TempContentGuid).tmp"
					if (-not ($DisableFunctionLogging)) { Write-Log -Message "ScriptBlock is too big, saving encrypted content in temp file [$($TempContentPath.FullName)] and executed as external script." -Severity 2 -Source ${CmdletName} }

					#  Convert original scriptblock to secure string
					$SecureString = ConvertTo-SecureString -String $ScriptBlock.ToString() -AsPlainText -Force

					#  Define random secure key bytes array
					$SecureKeyBytesArray = [System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid.Replace("-", ""))

					#  Save secure string encrypted in temp file
					$Utf8BomEncoding = New-Object System.Text.UTF8Encoding $true
					$SecureString | ConvertFrom-SecureString -Key $SecureKeyBytesArray | ForEach-Object { [System.IO.File]::WriteAllLines($TempContentPath, $_, $Utf8BomEncoding) }

					## Creates the ScriptBlock with parameters
					$SavedScriptBlockParameters = "[Byte[]]`$SecureKeyBytesArray = [string]('$($SecureKeyBytesArray -join " ")') -split ' '; [IO.FileInfo]`$TempContentPath = '$($TempContentPath.FullName)'"

					[scriptblock]$SavedScriptBlockBody = {
						#  Get encrypted content from temp file
						$SecureContent = Get-Content -LiteralPath $TempContentPath -Raw

						#  Delete temp file
						$null = Remove-Item -LiteralPath $TempContentPath -Force -ErrorAction Ignore

						#  Decrypt content to secure string
						$SecureContentString = $SecureContent | ConvertTo-SecureString -Key $SecureKeyBytesArray

						#  Convert secure string to unsecure string
						$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureContentString)
						$UnsecureContentString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
						[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

						#  Save unsecure string as scriptblock
						$ScriptBlock = [ScriptBlock]::Create($UnsecureContentString)

						#  Invoke scriptblock
						Invoke-Command -ScriptBlock $ScriptBlock -NoNewScope
					}

					$SavedScriptBlock = [scriptblock]::Create((($SavedScriptBlockParameters, $SavedScriptBlockBody.ToString()) -join ";"))

					## Defines encoded ScriptBlock ArgumentList parameter
					$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SavedScriptBlock))
					$EncodedArgumentList = "-ExecutionPolicy Bypass -Window Normal -EncodedCommand $($EncodedCommand)"
				}
				catch {
					Write-Log -Message "An error occured when trying to save encrypted ScriptBlock to temp folder [$TempPath].`r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					if (-not $ContinueOnError) {
						if ($ExitOnProcessFailure) {
							Exit-Script -ExitCode 70603
						}
						throw "An error occured when trying to save encrypted ScriptBlock to temp folder [$TempPath]:  $($_.Exception.Message)"
					}
					return
				}
			}

			## Defines encoded ScriptBlock ArgumentList parameter
			$ArgumentList = $EncodedArgumentList
		}

		if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
			[IO.FileInfo]$WorkingDirectory = Split-Path $Path -Parent
		}

		if (-not ($DisableFunctionLogging)) {
			Write-Log -Message "Working Directory is [$WorkingDirectory]." -Source ${CmdletName}

			if ($SecureArgumentList) {
				Write-Log -Message "Executing [$Path (Parameters Hidden)]..." -Source ${CmdletName}
			}
			elseif ($ScriptPath) {
				Write-Log -Message "Executing [$Path $ArgumentList]..." -Source ${CmdletName} 
			}
			else {
				Write-Log -Message "Executing [$Path [PowerShell ScriptBlock]]..." -Source ${CmdletName} 
			}
		}

		if ($SessionZero) {
			$Privileges = [RunAsActiveUser.ProcessExtensions]::GetTokenPrivileges()["SeDelegateSessionUserImpersonatePrivilege"]
			if (-not $Privileges -or ($Privileges -band [RunAsActiveUser.PrivilegeAttributes]::Disabled)) {
				Write-Log -Message "Not running with correct privilege. You must run this script as system or have the 'SeDelegateSessionUserImpersonatePrivilege' token." -Severity 3 -Source ${CmdletName}
				if (-not $ContinueOnError) {
					if ($ExitOnProcessFailure) {
						Exit-Script -ExitCode 70604
					}
					throw "Not running with correct privilege. You must run this script as system or have the 'SeDelegateSessionUserImpersonatePrivilege' token."
				}
				elseif ($FallbackToOriginalFunctionOnError) {
					Invoke-Command -ScriptBlock $FallbackToOriginalFunction -NoNewScope
				}
				return
			}
			else {
				try {
					switch ($RunLevel) {
						"HighestAvailable" { $RunAsAdmin = $true }
						"LeastPrivilege" { $RunAsAdmin = $false }
					}

					if ($Wait) {
						$WaitTime = -1
						if (-not ($DisableFunctionLogging)) { Write-Log -Message "Wait parameter specified. The function will wait until process termination." -Source ${CmdletName} }
					}
					else {
						$WaitTime = 1
					}

					$Return = [RunAsActiveUser.ProcessExtensions]::StartProcessAsCurrentUser([NullString]::Value, "`"$($Path.FullName)`" $($ArgumentList)", $WorkingDirectory.ToString(), $ShowWindow, $WaitTime, $RunAsAdmin, $CaptureOutput)

					if ($CaptureOutput) {
						if (-not ($DisableFunctionLogging)) {
							if ($SecureArgumentList) {
								Write-Log -Message "CaptureOutput parameter specified, returning secured Standard Output string." -Source ${CmdletName}
							}
							else {
							 Write-Log -Message "CaptureOutput parameter specified, returned Standard Output string [$Return]." -Source ${CmdletName}
							}
						}
						return $Return
					}
				}
				catch {
					Write-Log -Message "Failed to execute process as currently logged on user.`r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					if (-not $ContinueOnError) {
						if ($ExitOnProcessFailure) {
							Exit-Script -ExitCode 70605
						}
						throw "Failed to execute process as currently logged on user: $($_.Exception.Message)"
					}
					elseif ($FallbackToOriginalFunctionOnError) {
						Invoke-Command -ScriptBlock $FallbackToOriginalFunction -NoNewScope
					}
					return
				}
			}
		}
		else {
			$ExecuteProcessParameters = @{}
			$ExecuteProcessParameters.Add("Path", $Path)

			if (-not [string]::IsNullOrEmpty($ArgumentList)) {
				$ExecuteProcessParameters.Add("Parameters", $ArgumentList)
			}
			$ExecuteProcessParameters.Add("SecureParameters", $SecureArgumentList)
			$ExecuteProcessParameters.Add("WorkingDirectory", $WorkingDirectory)

			if (-not $ShowWindow) {
				$ExecuteProcessParameters.Add("CreateNoWindow", $true)
				$ExecuteProcessParameters.Add("WindowStyle", "Hidden")
			}
	
			$ExecuteProcessParameters.Add("ExitOnProcessFailure", $ExitOnProcessFailure)
			$ExecuteProcessParameters.Add("ContinueOnError", $ContinueOnError)

			if ($Wait) {
				if ($CaptureOutput) {
					$ExecuteProcessParameters.Add("PassThru", $true)
					$Return = Execute-Process @ExecuteProcessParameters
					return $Return.StdOut
				}
				else {
					$null = Execute-Process @ExecuteProcessParameters
				}
			}
			else {
				$ExecuteProcessParameters.Add("NoWait", $true)
				$null = Execute-Process @ExecuteProcessParameters
			}
		}
	}
	End {
		if ($Wait -and $TempContentGuid) {
			## Remove ecnrypted temp file if exists
			Remove-File -Path $TempContentPath -ContinueOnError $true
		}

		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Remove-Comments
Function Remove-Comments {
	<#
	.SYNOPSIS
		Strips comments and extra whitespace from a script.
	.DESCRIPTION
		Remove-Comments strips out comments and unnecessary whitespace from a script. This is best used in conjunction with Out-EncodedCommand when the size of the script to be encoded might be too big.
		A major portion of this code was taken from the Lee Holmes' Show-ColorizedContent script. You rock, Lee!
	.PARAMETER Path
		Specifies the path to your script.
	.PARAMETER ScriptBlock
		Specifies a scriptblock containing your script.
	.INPUTS
		System.String, System.Management.Automation.ScriptBlock
		Accepts either a string containing the path to a script or a scriptblock.
	.OUTPUTS
		System.Management.Automation.ScriptBlock
		Remove-Comment returns a scriptblock. Call the ToString method to convert a scriptblock to a string, if desired.
	.EXAMPLE
		$Stripped = Remove-Comments -Path .\ScriptWithComments.ps1
	.EXAMPLE
		Remove-Comments -ScriptBlock {
		### This is my awesome script. My documentation is beyond reproach!
			Write-Host 'Hello, World!' ### Write 'Hello, World' to the host
		### End script awesomeness
		}
		Write-Host 'Hello, World!'
	.EXAMPLE
		Remove-Comments -Path Inject-Shellcode.ps1 | Out-EncodedCommand
		Description
		-----------
		Removes extraneous whitespace and comments from Inject-Shellcode (which is notoriously large) and pipes the output to Out-EncodedCommand.
	.NOTES
		PowerSploit Function: Remove-Comment  
		Author: Matthew Graeber (@mattifestation)
		License: BSD 3-Clause  
		Required Dependencies: None  
		Optional Dependencies: None  
		Part of Run As Active User Extension
	.LINK
		https://github.com/LFM8787/PSADT.RunAsActiveUser
		https://psappdeploytoolkit.com
		http://psappdeploytoolkit.com
		http://www.exploit-monday.com
		http://www.leeholmes.com/blog/2007/11/07/syntax-highlighting-in-powershell/
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
	[CmdletBinding( DefaultParameterSetName = "ScriptBlock" )]
	Param (
		[Parameter(Position = 0, Mandatory = $True, ParameterSetName = "FilePath" )]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = "ScriptBlock" )]
		[ValidateNotNullOrEmpty()]
		[scriptblock]$ScriptBlock,
		[boolean]$ExitOnProcessFailure = $true,
		[boolean]$ContinueOnError = $false
	)

	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		## Trying to read the script file or parse the scriptblock
		try {
			if ($PSCmdlet.ParameterSetName -eq "FilePath") {
				$null = Get-ChildItem $Path -ErrorAction Stop
				$ScriptBlockString = [IO.File]::ReadAllText((Resolve-Path $Path))
				$ScriptBlock = [ScriptBlock]::Create($ScriptBlockString)
			}
			elseif ($PSCmdlet.ParameterSetName -eq "ScriptBlock") {
				#  Convert the scriptblock to a string so that it can be referenced with array notation
				$ScriptBlockString = $ScriptBlock.ToString()
			}
		}
		catch {
			Write-Log -Message "Error ocurred when reading source file/scriptblock.`r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			if (-not $ContinueOnError) {
				if ($ExitOnProcessFailure) {
					Exit-Script -ExitCode 70606
				}
				throw "Error ocurred when reading source file/scriptblock: $($_.Exception.Message)"
			}
			return
		}

		try {
			## Tokenize the scriptblock and return all tokens except for comments
			$Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptBlock, [Ref] $Null) | Where-Object { $_.Type -ne "Comment" }

			$StringBuilder = New-Object Text.StringBuilder

			## The majority of the remaining code comes from Lee Holmes' Show-ColorizedContent script.
			$CurrentColumn = 1
			$NewlineCount = 0
			foreach ($CurrentToken in $Tokens) {
				#  Now output the token
				if (($CurrentToken.Type -eq "NewLine") -or ($CurrentToken.Type -eq "LineContinuation")) {
					$CurrentColumn = 1
					#  Only insert a single newline. Sequential newlines are ignored in order to save space.
					if ($NewlineCount -eq 0) {
						$null = $StringBuilder.AppendLine()
					}
					$NewlineCount++
				}
				else {
					$NewlineCount = 0

					#  Do any indenting
					if ($CurrentColumn -lt $CurrentToken.StartColumn) {
						#  Insert a single space in between tokens on the same line. Extraneous whiltespace is ignored.
						if ($CurrentColumn -ne 1) {
							$null = $StringBuilder.Append(" ")
						}
					}

					#  See where the token ends
					$CurrentTokenEnd = $CurrentToken.Start + $CurrentToken.Length - 1

					#  Handle the line numbering for multi-line strings
					if (($CurrentToken.Type -eq "String") -and ($CurrentToken.EndLine -gt $CurrentToken.StartLine)) {
						$LineCounter = $CurrentToken.StartLine
						$StringLines = $( -join $ScriptBlockString[$CurrentToken.Start..$CurrentTokenEnd] -split '`r`n')

						foreach ($StringLine in $StringLines) {
							$null = $StringBuilder.Append($StringLine)
							$LineCounter++
						}
					}
					#  Write out a regular token
					else {
						$null = $StringBuilder.Append((-join $ScriptBlockString[$CurrentToken.Start..$CurrentTokenEnd]))
					}

					#  Update our position in the column
					$CurrentColumn = $CurrentToken.EndColumn
				}
			}

			return [ScriptBlock]::Create($StringBuilder.ToString())
		}
		catch {
			Write-Log -Message "Error ocurred when removing comments from source file/scriptblock.`r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			if (-not $ContinueOnError) {
				if ($ExitOnProcessFailure) {
					Exit-Script -ExitCode 70607
				}
				throw "Error ocurred when removing comments from source file/scriptblock: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#endregion
##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================
#region ScriptBody

if ($scriptParentPath) {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $RunAsActiveUserExtName
}
else {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $RunAsActiveUserExtName
}

## Add the custom types required for the extension
if (-not ([Management.Automation.PSTypeName]"RunAsActiveUser.ProcessExtensions").Type) {
	Add-Type -Path $RunAsActiveUserCustomTypesSourceCode -IgnoreWarnings -ErrorAction Stop
}

#  Defines the original functions to be renamed
if ($configRunAsActiveUserGeneralOptions.ReplaceOriginalExecuteProcessAsUser) {
	$FunctionsToRename += [PSCustomObject]@{
		Scope = "Script"
		Name  = "Execute-ProcessAsUser"
		Value = $(${Function:Invoke-ProcessAsActiveUser}.ToString())
	}
	$FunctionsToRename | ForEach-Object { New-DynamicFunction -Name $_.Name -Scope $_.Scope -Value $_.Value }
}

#endregion
##*===============================================
##* END SCRIPT BODY
##*===============================================
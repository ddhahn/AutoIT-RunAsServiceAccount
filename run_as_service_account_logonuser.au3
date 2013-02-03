#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Compression=4
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#AutoIt3Wrapper_Add_Constants=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
; *** Start added by AutoIt3Wrapper ***
#include <StructureConstants.au3>
; *** End added by AutoIt3Wrapper ***



;+--- David Hahn 2/13/2012
;+--- Script Run as service account using LogonUser, duplicatetokenex and createprocessasuser
;+--- Arguments to this script should be the command line you want to run. if double quotes are necessary, then use them. They will be passed along.
#include "date.au3"
;#include "winapi.au3"
#include <winapiex.au3>
#include <apiconstants.au3>
#include <security.au3>

;+---- version notes
;+--- 1.0 - first version
;+--- 1.1 - change to start the process with the users environment and load the user profile as well.
;+--- 1.2 - change to compile with autoit 3.3.8.1

;+--- Check these links for documentation on functions used in this script
;Win32 function LogonUser --> http://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx
;Win32 function DuplicateTokenEx --> http://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx
;Win32 function CreateProcessAsUser --> http://msdn.microsoft.com/en-us/library/windows/desktop/ms682429(v=vs.85).aspx
;Win32 function GetExitCodeProcess --> http://msdn.microsoft.com/en-us/library/windows/desktop/ms683189(v=vs.85).aspx
;AutoIT function DLLCall --> http://www.autoitscript.com/autoit3/docs/functions/DllCall.htm
;used Example for LSA functions from here --> http://zhidao.baidu.com/question/96985178.html
;Win32 function LookupAccountName --> http://msdn.microsoft.com/en-us/library/windows/desktop/aa379159(v=vs.85).aspx
;Win32 function LsaOpenPolicy --> http://msdn.microsoft.com/en-us/library/windows/desktop/aa378299(v=vs.85).aspx
;Win32 function LsaAddAccountRights --> http://msdn.microsoft.com/en-us/library/windows/desktop/ms721786(v=vs.85).aspx
;Win32 function LsaClose --> http://msdn.microsoft.com/en-us/library/windows/desktop/ms721787(v=vs.85).aspx

#region Global Constants
Global Const $LOGON32_LOGON_INTERACTIVE = 2
Global Const $LOGON32_LOGON_NETWORK = 3
Global Const $LOGON32_LOGON_BATCH = 4
Global Const $LOGON32_LOGON_SERVICE = 5
Global Const $LOGON32_LOGON_UNLOCK = 7
Global Const $LOGON32_LOGON_NETWORK_CLEARTEXT = 8
Global Const $LOGON32_LOGON_NEW_CREDENTIALS = 9
Global Const $MAXIMUM_ALLOWED = 0x02000000
Global Const $LOGON32_PROVIDER_DEFAULT = 0
Global Const $LOGON32_PROVIDER_WINNT35 = 1
Global Const $LOGON32_PROVIDER_WINNT40 = 2
Global Const $LOGON32_PROVIDER_WINNT50 = 3
;Global Const $SECURITYIDENTIFICATION = 1 ;+--- no longer needed for autoit 3.3.8.1
;GLobal Const $TOKENPRIMARY = 1 ;+--- no longer needed for autoit 3.3.8.1
Global Const $tagPROCESSINFO = "ptr hProcess;ptr hThread;dword dwProcessId;dword dwThreadId"
Global Const $VERSION = "1.2"
#endregion


#region Service Account username and password
Global $sUserName = "username"
Global $sDomain = "contoso.com	"
Global $sPassword = "password"
#endregion

#region Local Variables
Local $phToken
Local $return_value = -99 ;+--- default return value. -99 indicates that the script was not successful.
Local $logfilepath = ""
#endregion

;+--- check that we're running in  LANDesk job.
if @UserName = "SYSTEM" Then

	;+--- we appear to be running as system
	WriteLogFile("-->We're running as SYSTEM",true)

	;+--- make sure we're running as system.
	if CheckForLANDeskEnv() then ;+--- we're running as SYSTEM, go forward.

		;+--- we appear to be running as part of a LANDesk job
		WriteLogFile("-->We appear to be running within a LANDesk job. LD_CLIENT_DIR is defined.",true)

		;+--- set the logging path
		$logfilepath = SetLogFilePath()

		;+--- Log the start of the script
		WriteLogFile("")
		WriteLogFile("--------Starting run as service account script--------")
		WriteLogFile("")

		;+--- check the arguments to make sure we have one argument. If not, output usage and quit.
		if $cmdline[0] = 0 then
			Usage()
			QuitScript($return_value)
		endIf

		;+--- check that the account specified has the logon as a service right. if not, add it.
		if CheckLogOnAsAServiceRight() then ;+--- we're able to log on as a service!

			;+--- Try to log on the service account as a service. This will only work if the service account is
			;+--- granted the logon as a service right!
			$ret_val = LogOnServiceAccount($susername,$sdomain,$sPassword)

			;+--- check if the logon was successful
			If @error = 0 and $ret_val[0] <> 0 Then ;+--- the logon was successful

				WriteLogFile("Successfully logged on user " & $sdomain & "\" & $sUsername,True)

				$phToken = $Ret_val[6] ;+--- this get's the pointer to the token that was generated in LogonUser

				;+--- try to load the user profile
				local $profilehandle
				$ret = _LoadUserProfile($phtoken,$susername,$profilehandle)

				if $ret[0] <> 0 Then ;+--- we loaded the profile OK
					WriteLogFile("Successfully loaded user profile.",true)

					;+--- start a process and wait
					Local $diditwork
					$ret_val = CreateProcessandWait($phtoken,$cmdlineraw,$diditwork)
					if $diditwork then ;+--- the function succeeded, so the return value is the return value of the exe.

						WriteLogFile("The process was ran and returned code " & $ret_val,true)
						$return_value = $ret_val ;+--- set the return value

						;+--- unload the user profile.
						$ret = _UnloadUserProfile($phtoken,$profilehandle)
						if $ret[0] <> 0 Then
							WriteLogFile("Successfully unloaded user profile.",true)
						Else

							$ret_val = DllCall("kernel32.dll", "int", "GetLastError")
							WriteLogFile("Could not unload user profile. UnloadUserProfile returned " & $ret_val[0],true)
						endIf

					Else ;+--- the return value is a error from CreateProcessAsUser

						$ret_val = DllCall("kernel32.dll", "int", "GetLastError")
						WriteLogFile("Couldn't start process. Error returned from CreateProcessAndWait was " & $ret_val[0],true)
						WriteLogFile("You can find what this error code means by running net helpmsg " & $ret_val[0],true)
						WriteLogFile("Be aware that this error message could have come from any API call within the CreateProcessAndWait function",true)
					EndIf
				Else
					$ret_val = DllCall("kernel32.dll", "int", "GetLastError")
					WriteLogFile("Could not load user profile. LoadUserProfile returned " & $ret_val[0],true)
				EndIf

			Else ;+--- logon was not successful. We can't do anything if we can't log in.

				$ret_val = DllCall("kernel32.dll", "int", "GetLastError")
				WriteLogFile("Logon of user " & $sUsername & " failed with code " & $ret_val[0],true)
				WriteLogFile("You can find what this error code means buy running net helpmsg " & $ret_val[0],true)

			EndIf

		Else ;+--- we couldn't set rights such that we could log on as a service

			WriteLogFile("Could not add logon as a service rights for "& $sdomain & "\" & $susername & ". Can not continue.",true)

		EndIf

		QuitScript($return_value)

	Else
		;+--- we're not running in a landesk environment!
		WriteLogFile("ERROR: This app should be run as part of a LANDesk distribution job! You appear to be running it stand-alone.",True)
		Usage()

	EndIf

Else
	;+--- we're not running as system
	WriteLogFile("ERROR: This app needs to be run as the SYSTEM account. You're running as " & @UserName,True)
	Usage()

EndIf



#region SupportingFunctions
;+--------------------------------------------------------------------------------------------
func Usage()
	;+---- output usage via the console and the log file.

	if $cmdline[0] =0 then WriteLogFile ('ERROR: Invalid number of arguments! You must specify at least one argument which specifies the exe to run.',True)

	WriteLogFile ("",True)
	WriteLogFile ("Script Version: " & $VERSION,True)
	WriteLogFile ("This utility is used to run commands as a service account.",True)
	WriteLogFile ("The account specified in the script will be granted Logon as a Service right.",True)
	WriteLogFile ("The exe will be run with the highest privileges on the system.",True)
	WriteLogFile ("32 bit and 64 bit Windows 7 and Windows XP are supported",True)
	WriteLogFile ("",True)
	WriteLogFile ('Usage: ',True)
	WriteLogFile ("",True)
	WriteLogFile (@scriptname & ' myapp.exe',True)
	WriteLogFile (@scriptname & ' myapp.exe /q /s',True)
	WriteLogFile (@scriptname & ' myapp.exe /q /s "another argument"',True)
	WriteLogFile (@scriptname & ' "\\server\my special share\myapp.exe" /q /s "another argument"',True)


EndFunc


func GetSID($user, $domain)
	;+--- function will return a SID structure to be used with LSA API's.
	;+--- Derived from here: http://zhidao.baidu.com/question/96985178.html
	;+--- the function calls LookupAccountName twice. Once to get how big the buffers need
	;+--- to be and once to actually get the data.
	;+--- documentation on LookUpAccountName is here:
	;+--- http://msdn.microsoft.com/en-us/library/windows/desktop/aa379159(v=vs.85).aspx

	Local $iResult, $tSid, $pSid, $tDomain, $pDomain

	;+--- calll LookupAccountName with only the username and domain to get buffer sizes and to validate
	;+--- that the domain\username is valid
	$iResult = DllCall("advapi32.dll", "int", "LookupAccountName", _
					"str", "", _ ;lpSystemName
					"str", $domain & "\" & $user, _ ;lpAccountName
					"ptr", 0, _ ;SID
					"int*", 0, _ ;cbSid
					"ptr", 0, _ ;ReferencedDomainName
					"int*", 0, _;cchReferencedDomainName
					"int*", 0 ) ;peUse
	;+--- if the cbsize is 0 that means the size couldn't be retrived. Probably because the account doesn't exist.
	If $iResult[4] = 0 Then Return SetError(2345, 0, 0)

	;+--- If we get here, it means the account exists. get the buffer sizes from the call and
	;+--- create some structures to receive the data.
	$tSid = DllStructCreate("ubyte[" & $iResult[4] & "]")
	$tDomain = DllStructCreate("ubyte[" & $iResult[6] & "]")
	$pSid = DllStructGetPtr($tSid)
	$pDomain = DllStructGetPtr($tDomain)

	;+--- now call the function again and receive the SID information.
	$iResult = DllCall("advapi32.dll", "int", "LookupAccountName", _
					"str", "" , _ ;lpSystemName
					"str", $domain & "\" & $user, _ ;lpAccountName
					"ptr", $pSid, _ ;SID
					"int*", $iResult[4], _ ;cbSid
					"ptr", $pDomain, _ ;ReferencedDomainName
					"int*", $iResult[6], _;cchReferencedDomainName
					"int*", 0) ;peUse

	;+--- return the information to the caller
	Return SetError(Not $iResult[0], $iResult[7], $tSid)

EndFunc

func CheckLogOnAsAServiceRight()

	;+--- check that the user has the logon as a service right by reading the local security policy
	;+--- This will involve
	;+--- 1. getting the SID of the account we want to use.
	;+--- 2. Open the policy
	;+--- 3. Add the logon as a service right.
	;+--- 4. return true if the function ends with the right being applied
	;+---    return false if the function ends with the right NOT being applied.

	;+--- parts are derived from here: http://zhidao.baidu.com/question/96985178.html
	;+--- mainly the parts about setting up the unicode string structure.

	local $return_value

	$return_value = false ;+--- assume failure.

	;+--- create some structures that we will need to call the LSA APi's
	Local $tagLSA_OBJECT_ATTRIBUTES = "ULONG Length;HANDLE RootDirectory;ptr ObjectName;ULONG Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
	Local $tagLSA_UNICODE_STRING = "USHORT Length;USHORT MaximumLength;ptr Buffer"

	;+--- define the structures needed for LSA calls.
	$LSA_OBJECT_ATTRIBUTES = DllStructCreate($tagLSA_OBJECT_ATTRIBUTES)
	$LSA_UNICODE_STRING = DllStructCreate($tagLSA_UNICODE_STRING)

	;+--- create the unicode string structure with the seServiceLogonRight defined
	Local $LOGON_AS_A_SERVICE_RIGHT_NAME = "SeServiceLogonRight"
	local $iLength = StringLen($LOGON_AS_A_SERVICE_RIGHT_NAME) * 2 ;+-- do this because the string will be unicode, not ansi.
	local $tRight = DllStructCreate("wchar[" & $iLength & "]") ;+-- create a unicode string and return a pointer.
	local $pRight = DllStructGetPtr($tRight) ;+--- get a pointer to the structure
	DllStructSetData($tRight,1,$LOGON_AS_A_SERVICE_RIGHT_NAME) ;+--- put the right string in the structure

	;+--- fill in the structure for logon as a service right
	DllStructSetData($LSA_UNICODE_STRING,"Length",$iLength)
	dllstructsetdata($LSA_UNICODE_STRING,"MaximumLength",$iLength+2)
	DllStructSetData($LSA_UNICODE_STRING,"Buffer",$pRight)

	;+--- set the length of the object attributes structure. This is the only attribute that should be set according to MSDN documenation.
	DllStructSetData($LSA_OBJECT_ATTRIBUTES, "Length", DllStructGetSize($LSA_OBJECT_ATTRIBUTES))

	;+--- get the sid of the user we want to add
	$Sid = GetSID($sUsername,$sdomain)
	if @error <> 2345 then ;+--- the SID is valid
		$sid_ptr = DllStructGetPtr($sid) ;+--- get a pointer to the SID that was passed back by the GetSID function.

		Local $handle
		;+--- open the local security policy object
		$ret = DllCall("advapi32.dll", "int", "LsaOpenPolicy", _
						   "ptr", 0, _
						   "ptr", DllStructGetPtr($LSA_OBJECT_ATTRIBUTES), _
						   "DWORD", 0xF0FFF, _
						   "ptr*", $handle)

		if $ret[0] = 0 then ;+--- we opened the local security policy successfully

			$policy_handle = $ret[4] ;+--- get the handle to the policy object and save it in $policy_handle
			WriteLogFile("Successfully obtained a handle to the local security policy", true)

			;+--- add the right to the policy.
			$ret = DllCall("advapi32.dll", "int", "LsaAddAccountRights", _
						   "hWnd", $policy_handle, _
						   "ptr", $sid_ptr, _
						   "DWORD", dllstructgetptr($LSA_UNICODE_STRING), _
						   "ULONG", 1)

			;+--- check the return code from lsaAddaccountrights. If it was successful, the function should return true.
			If $ret[0] = 0 Then
				WriteLogFile("Successfully added " & $sdomain & "\" & $sUsername & " as having Logon as a Service right..",true)
				$return_value = True
			Else ;+-- we couldn't add the serviceaccountlogon right.
				WriteLogFile("Failed to add " & $sdomain & "\" & $sUsername & " as having Logon as a Service right..",true)
			EndIf

			;+--- close the handle to the local security policy.
			$ret = DllCall("advapi32.dll", "int", "LsaClose", _
					"ptr", $policy_handle)

			;+--- check that we were able to close the handle to the local security log.
			if $ret[0] = 0 then
				WriteLogFile("Successfully closed handle to Local Security Policy",True)
			Else
				WriteLogFile("Error while closing handle to Local Security Policy. Memory may be leaked.",true)
			EndIf

		Else ;+--- we didn't open the policy successfully.
			WriteLogFile("Error opening the local security policy. LsaOpenPolicy returned " & $ret[0],true)

		EndIf
	Else ;+--- the domain\username combination passed appears to be invalid. Probably misspelled the domain or username.
		WriteLogFile("The account " & $sdomain & "\" & $sUsername & " could not be translated into a valid SID. Check the spelling of the domain and user name.",True)
	EndIf

	;+--- return the true\false value from the function.
	return($return_value)

EndFunc

func SetLogFilePath()
	;+--- this function will return a path to a file that will be used for logging
	;+--- the function takes into account if the HDR specific logging directory exists
	;+--- This assumes that LD_Client_DIR will evaluate to SOMETHING. Don't call unless you
	;+--- want unpredictable behavior.

	;+--- define the filename
	local $filename = "HDR_" & StringLeft(@scriptname,stringlen(@scriptname)-4) & ".txt"
	;+--- filedirectory will contain the directory which the log file should reside.
	local $filedirectory

	$LDClientDir = envget("LD_CLIENT_DIR") ;+--- get the ld client directory.
	if not FileExists($LDClientDir & "\HDR-InstLogs\") then ;+--- check that the hdr-instlogs directory
		if dircreate($LDClientDir & "\HDR-InstLogs\") <> 0 Then ;+--- we sucessfully created the directory
			$filedirectory = $LDClientDir & "\HDR-InstLogs\" ;+--- set the filedirectory variable to the HDR-instlogs directory
			WriteLogFile("-->Created " & $LDClientDir & "\HDR-InstLogs\ succesfully. Logging to " & $filedirectory) ;+--- output to the console that we created the directory.
		Else
			$filedirectory = @TempDir & "\" ;+--- we couldn't create the directory, but we need to log somewhere. So log to @tempdir.
			WriteLogFile("-->Error creating " & $LDClientDir & "\HDR-InstLogs\. Logging to " & $filedirectory)
		EndIf
	else ;+---the directory already exists! log there
		$filedirectory = $LDClientDir & "\HDR-InstLogs\"
		WriteLogFile("-->Logging to " & $filedirectory)
	EndIf

	WriteLogFile ("") ;+---- insert an extra line into the console. It looks cleaner.

	return($filedirectory & $filename) ;+--- return the whole path to the file.

EndFunc

func CheckForLANDeskEnv()

	;+--- check that the environment variable ld_client_dir exists. If this exists, then we presume we're running
	;+--- as part of a LANDesk software distribution job so return true. Otherwise, return false.
	if envget("LD_CLIENT_DIR") <> "" then
		return True
	Else
		return false
	EndIf

EndFunc

func CreateProcessandWait($token,$AppPath, byref $success)
		;+--- now that we have a duplicate token, let's run a process as that user
		;+--- for usage of CreateProcessasUserW, see the links in the comments above

		;+--- This function also creates a desktop called sparedesktop and runs the process on that desktop
		;+--- This will prevent any dialogs that the process will show from popping up on the users desktop

		;+--- set the creation flags
		Local $dwCreationFlags = BitOR($NORMAL_PRIORITY_CLASS,$CREATE_UNICODE_ENVIRONMENT)

		;+--- Create the startupinfo and processinfo structures that need to be passed to CreateProcessAsUserW
		Local $SI = DllStructCreate($tagSTARTUPINFO)
		Local $PI = DllStructCreate($tagPROCESSINFO)

		;+--- create a new desktop to start the process on so that it doesn't show any windows to the user
		;+--- Retrieve a handle to the current desktop and create a new desktop named "sparedesktop"
		$hDesktop = _WinAPI_CreateDesktop('sparedesktop', BitOR($DESKTOP_CREATEWINDOW, $DESKTOP_SWITCHDESKTOP))
		If Not $hDesktop Then
			WriteLogFile("Could not create desktop!",true)
			$success=False
			Return(-99)
		Else
			WriteLogFile("Successfully created sparedesktop",true)
		EndIf

		;+--- create a pointer to a string that has the name of our desktop in it
		$pText = _WinAPI_CreateString('sparedesktop')
		DllStructSetData($SI, "Desktop", $pText)

		;+--- set the size of the SI structure
		DllStructSetData($SI, "cb", DllStructGetSize($SI))

		;+--- need to set the environment block for the user.
		Local $env_ptr ;+---- pointer to the environment block for the user.
		;+--- Get the environment from the loggedon user's token
		$ret = DllCall("Userenv.dll", "int", "CreateEnvironmentBlock", _
			   "ptr*", 0, _
			   "ptr",$token, _
			   "int", 1)

		if $ret[0] = 0 then ;+---the call did not succeed.
			WriteLogFile("Could not get environment block for user " & $sdomain & "\" & $susername & "!",true)
			$success=False
			Return(-99)
		Else
			WriteLogFile("Successfully retrieved environment block for "& $sdomain & "\" & $susername,true)
			$env_ptr = $ret[1] ;+--- get the pointer to the environment block.
		EndIf

		;+--- log that we're trying to start the process
		WriteLogFile("Trying to start command line: '" & $AppPath & "' as "  & $sdomain & "\" & $sUsername,true)

		;+---- Call createproecssasuserw using the token and application path passed to the function
		$ret = DllCall("advapi32.dll", "int", "CreateProcessAsUserW", _
					   "ptr", $token, _
					   "ptr", 0, _
					   "wstr", $AppPath, _
					   "ptr", 0, _
					   "ptr", 0, _
					   "int", 0, _
					   "dword", $dwCreationFlags, _
					   "ptr", $env_ptr, _
					   "ptr", 0, _
					   "ptr", DllStructGetPtr($SI), _
					   "ptr", DllStructGetPtr($PI))

		;+--- check that we were able to start the process by checking @error and the return value of the function call.
		If Not @error And $ret[0] Then

			WriteLogFile ("Created new process with PID " & DllStructGetData($PI, "dwProcessId") & " on sparedesktop",true)
			WriteLogFile ("Now waiting for process to exit..",true)
			;+--- we now need to wait on that object and ultimately return what it returns. Use waitforsingleobject api call to accomplish this.
			;+--- passing -1 as the second argument to the function call means it will wait forever until the process exits.
			$hProcHandle = DllStructGetData($PI,"hProcess")
			$ret = DllCall("kernel32.dll","DWORD","WaitForSingleObject", _
						   "ptr",$hProcHandle, _
						   "DWORD", -1)

			local $retval

			;+--- after waitforsingleobject returns, get the return code using getexitcodeprocess
			$ret = DllCall("kernel32.dll","int","GetExitCodeProcess", _
						   "ptr",$hProcHandle, _
						   "ptr*", $retval )

			;+--- delete sparedesktop
			$close_ret = _WinAPI_CloseDesktop($hDesktop)
			if $close_ret = 1 then
				WriteLogFile("Successfully closed sparedesktop",true)
			Else
				WriteLogFile("Could not close sparedesktop",true)
			EndIf

			;+--- don't need the environment block any more
			$destroy_ret = DllCall("userenv.dll", "int", "DestroyEnvironmentBlock", _
							"ptr", $env_ptr)

			if $destroy_ret[0] <> 0 then
				WriteLogFile("Successfully destroyed environment block.",true)
			Else
				WriteLogFile("Could not destroy environment block.",true)
			EndIf
			;+--- free up memory and set return codes
			$success=True
			_WinAPI_FreeMemory($pText)

			$SI=""
			$PI=""
			return($ret[2])
		Else
			;+--- delete sparedesktop
			$close_ret = _WinAPI_CloseDesktop($hDesktop)
			if $close_ret = 1 then
				WriteLogFile("Successfully closed sparedesktop",true)
			Else
				WriteLogFile("Could not close sparedesktop",true)
			EndIf

			;+--- free up memory and set return codes
			_WinAPI_FreeMemory($pText)
			$success=False
			return($ret[0])

		EndIf

EndFunc


func DuplicateServiceAccountToken ($tokentoduplicate)

	local $duptoken ;+--- need a variable to hold a pointer to the duplicated token we will need

	;+--- duplicate the token so we can use it to launch a process
	Local $ret = DllCall("advapi32.dll", "int", "DuplicateTokenEx", _
								"ptr", $tokentoduplicate, _
								"dword", $MAXIMUM_ALLOWED, _
								"ptr", 0, _
								"int", $SECURITYIDENTIFICATION, _
								"int", $TOKENPRIMARY, _
								"ptr*", $duptoken)

	return $ret
EndFunc

func _UnloadUserProfile($intoken,$inhandle)

	;+--- unload the users profile specified by $token and $handle
	$Ret = DllCall("Userenv.dll", "int", "UnloadUserProfile", _
		"ptr", $intoken, _
		"ptr", $inhandle)

	return($ret)

EndFunc


func _LoadUserProfile($token,$user,byref $profilehandle)
	;+--- load the user profile for user in $token
	;+--- http://msdn.microsoft.com/en-us/library/windows/desktop/bb762281(v=vs.85).aspx

	;+--- need to define the profileinfo structure
	local $PROFILEINFO
	$PROFILEINFO=DllStructCreate("DWORD dwSize;DWORD dwFlags;ptr lpUserName;ptr lpProfilePath;ptr lpDefaultPath;ptr lpServerName;ptr lpPolicyPath;HANDLE hProfile")

	DLLstructsetdata($PROFILEINFO,"dwFlags",1)
	$user_ptr = _WinAPI_CreateString($user) ;+--- get an ascii string.
	DllStructSetData($PROFILEINFO,"lpUserName",$user_ptr)
	DllStructSetData($PROFILEINFO,"dwSize",DllStructGetSize($PROFILEINFO))
	;+--- call the unicode version of LoadUserProfile function because the PROFILEINFO structure has a unicode string in it.
	$Ret = DllCall("Userenv.dll", "int", "LoadUserProfileW", _
		"ptr", $token, _
		"ptr", DllStructGetPtr($PROFILEINFO))

	if $ret[0] <> 0 Then $profilehandle=DllStructGetData($PROFILEINFO,"hProfile")
	_WinAPI_FreeMemory($user_ptr)

	return($ret)

EndFunc

;+--- Try to logon the user with the credentials passed.
func LogOnServiceAccount($username,$domain,$password)

	;+--- try to log on the user using Win32 function LogonUser
	WriteLogFile("Trying to logon user " & $domain & "\" & $UserName & "..",true)

	$Ret = DllCall("advapi32.dll", "int", "LogonUser", _
		"str", $Username, _
		"str", $Domain, _
		"str", $Password, _
		"int", $LOGON32_LOGON_SERVICE, _
		"int", $LOGON32_PROVIDER_DEFAULT, _
		"ptr*", $phToken)



	return $ret

EndFunc

;+--- write the end of the log and exit with the value passed to the function
Func QuitScript($value)
	WriteLogFile("")
	WriteLogFile("--------Ending run as service account script--------")
	WriteLogFile("")

	exit($value)

EndFunc

;+--- write a log file and\or the console with or without a timestamp
Func WriteLogFile($stringtowrite, $consolewrite=False)

	;+-- check that the logfilepath variable is valid. If not, skip logging to it and just log to the console.
	if $logfilepath <> "" then
		$logfile = fileopen($logfilepath,1)
		filewrite($logfile,'[' & _NowDate() & ' ' & _Nowtime() & '] - ' & $stringtowrite & @crlf)
		fileclose($logfile)
	EndIf

	if $consolewrite=true then ConsoleWrite($stringtowrite & @crlf)


EndFunc
#endregion

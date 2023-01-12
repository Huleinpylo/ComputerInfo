

Add-Type -AssemblyName System.Windows.Forms
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

[System.Windows.Forms.Application]::EnableVisualStyles()

$Pylo_Prep_Automatisation      = New-Object system.Windows.Forms.Form
$Pylo_Prep_Automatisation.ClientSize  = New-Object System.Drawing.Point(800,400)
$Pylo_Prep_Automatisation.minimumSize = New-Object System.Drawing.Size(800,490) 
$Pylo_Prep_Automatisation.maximumSize = New-Object System.Drawing.Size(800,490)
$Pylo_Prep_Automatisation.text  = "Audit Huleinpylo"
$Pylo_Prep_Automatisation.TopMost  = $false
wget ("https://www.scs.net.nz/assets/aafa67d0d2/IT_Service1-1024x439.jpg") -UseBasicParsing -OutFile "Backgroung.jpg"
$Pylo_Prep_AutomatisationImage = [system.drawing.image]::FromFile("Backgroung.jpg")
$Pylo_Prep_Automatisation.BackgroundImage = $Pylo_Prep_AutomatisationImage
$Pylo_Prep_Automatisation.BackgroundImageLayout = "None"
#$Pylo_Prep_Automatisation.BackColor  = [System.Drawing.ColorTranslator]::FromHtml("#cdf8ec")

$UPDATE_LAUNCH                   = New-Object system.Windows.Forms.Button
$UPDATE_LAUNCH.text              = "Valider"
$UPDATE_LAUNCH.width             = 160
$UPDATE_LAUNCH.height            = 40
$UPDATE_LAUNCH.location          = New-Object System.Drawing.Point(450,330)
$UPDATE_LAUNCH.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$CLIENT_NAME                     = New-Object system.Windows.Forms.Label
$CLIENT_NAME.text                = "Client"
$CLIENT_NAME.AutoSize            = $true
$CLIENT_NAME.width               = 25
$CLIENT_NAME.height              = 10
$CLIENT_NAME.location            = New-Object System.Drawing.Point(20,330)
$CLIENT_NAME.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$TECHNITIEN                      = New-Object system.Windows.Forms.Label
$TECHNITIEN.text                 = "Auditeur"
$TECHNITIEN.AutoSize             = $true
$TECHNITIEN.width                = 25
$TECHNITIEN.height               = 10
$TECHNITIEN.location             = New-Object System.Drawing.Point(20,80)
$TECHNITIEN.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$EMPLACEMENT                     = New-Object system.Windows.Forms.Label
$EMPLACEMENT.text                = "Emplacement"
$EMPLACEMENT.AutoSize            = $true
$EMPLACEMENT.width               = 25
$EMPLACEMENT.height              = 20
$EMPLACEMENT.location            = New-Object System.Drawing.Point(20,200)
$EMPLACEMENT.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',15)
$TECHNITIEN_TEXT                 = New-Object system.Windows.Forms.TextBox
$TECHNITIEN_TEXT.multiline       = $false
$TECHNITIEN_TEXT.text            = ""
$TECHNITIEN_TEXT.width           = 181
$TECHNITIEN_TEXT.height          = 20
$TECHNITIEN_TEXT.location        = New-Object System.Drawing.Point(20,140)
$TECHNITIEN_TEXT.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$EMPLACEMENT_TEXT                = New-Object system.Windows.Forms.TextBox
$EMPLACEMENT_TEXT.multiline      = $false
$EMPLACEMENT_TEXT.text           = ""
$EMPLACEMENT_TEXT.width          = 181
$EMPLACEMENT_TEXT.height         = 20
$EMPLACEMENT_TEXT.location       = New-Object System.Drawing.Point(20,260)
$EMPLACEMENT_TEXT.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$CLIENT_TEXT                     = New-Object system.Windows.Forms.TextBox
$CLIENT_TEXT.multiline           = $false
$CLIENT_TEXT.text                = ""
$CLIENT_TEXT.width               = 180
$CLIENT_TEXT.height              = 20
$CLIENT_TEXT.location            = New-Object System.Drawing.Point(20,380)
$CLIENT_TEXT.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',15)

$Pylo_Prep_Automatisation.controls.AddRange(@($UPDATE_LAUNCH,$CLIENT_NAME,$TECHNITIEN,$EMPLACEMENT,$TECHNITIEN_TEXT,$EMPLACEMENT_TEXT,$CLIENT_TEXT))


$UPDATE_LAUNCH.Add_Click({


    New-Item -Path "HKLM:\Software" -Name "PYLO" –Force
    New-Item -Path "HKLM:\Software\PYLO" -Name "0" –Force
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "CLIENT" -Type STRING -Value $CLIENT_TEXT.Text
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Emplacement" -Type STRING -Value $EMPLACEMENT_TEXT.Text
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Technicien" -Type STRING -Value $TECHNITIEN_TEXT.Text
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "User_Session" -Type STRING -Value (whoami)
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "MDP_Session" -Type STRING -Value "INVENTAIRE"
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "User_Admin" -Type STRING -Value "ADMIN"
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "MDP_ADMIN" -Type STRING -Value "0Xff"
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Nom_de_L_Ordinateur" -Type STRING -Value ($env:COMPUTERNAME)
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Hostname" -Type STRING -Value ([System.Net.Dns]::GetHostByName($env:computerName).HostName)
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Workgroup" -Type STRING -Value ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup)
    $var=Get-Item ("C:\Users\*") | ?{$_.Name -ne "Public"} 
    $date=get-date
    $var | % {if($_.CreationTime -le $date) {$date=$_.CreationTime}}
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "Date_Install" -Type STRING -Value ($Date.ToString("yyyy MM dd"))
    Set-ItemProperty -Path "HKLM:\Software\PYLO\0" -Name "INV_New" -Type STRING -Value ("INV")
    

    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
    Enable-PSRemoting -Force
    Set-NetFirewallRule -Name WINRM-HTTP-In-TCP -RemoteAddress Any
    Get-NetTCPConnection | Where-Object -Property LocalPort -eq 5985
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force


    


#testing phase 
mkdir "C:\Pylo\"
$CompanyLogo = "https://cdn.logo.com/hotlink-ok/logo-social.png"
$RightLogo = "https://cdn.logo.com/hotlink-ok/logo-social.png"
$ReportSavePath = "C:\Pylo\"


if( (Get-Command -Module Posh-SSH ) -eq $null)
{
    Install-PackageProvider -Name NuGet -Force
    Install-Module Posh-SSH -Force
}
function Get-TVID {

    param(
        [string] $Hostname,
        [switch] $Copy
        )


    #Variables
    $Target = $Hostname
    If (!$Target) {$Target = $env:COMPUTERNAME}
    
    
    #Start Remote Registry Service
    If ($Target -ne $env:COMPUTERNAME) {
        $Service = Get-Service -Name "Remote Registry" -ComputerName $Target
        $Service.Start()
    }


    #Suppresses errors (comment to disable error suppression)
    $ErrorActionPreference = "SilentlyContinue"


    #Attempts to pull clientID value from remote registry and display it if successful
    $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Target)
    $RegKey= $RegCon.OpenSubKey("SOFTWARE\\WOW6432Node\\TeamViewer")
    $ClientID = $RegKey.GetValue("clientID")


    #If previous attempt was unsuccessful, attempts the same from a different location
    If (!$clientid) {
        $RegKey= $RegCon.OpenSubKey("SOFTWARE\\WOW6432Node\\TeamViewer\Version9")
        $ClientID = $RegKey.GetValue("clientID")
    }


    #If previous attempt was unsuccessful, attempts the same from a different location
    If (!$clientid) {
        $RegKey= $RegCon.OpenSubKey("SOFTWARE\\TeamViewer")
        $ClientID = $RegKey.GetValue("clientID")
    }


    #Stop Remote Registry service
    If ($Target -ne $env:COMPUTERNAME) {
        $Service.Stop()
    }


    #Display results
    Write-Host
    If (!$clientid) {Write-Host "ERROR: Unable to retrieve clientID value via remote registry!" -ForegroundColor Red}
    Else {Write-Host "TeamViewer client ID for $Target is $Clientid." -ForegroundColor Yellow}
    
    Write-Host
    


    #Copy to clipboard
    If ($copy -and $ClientID) {$ClientID | clip}

    return $clientid;
}

$OS_Name=(Get-CimInstance  -class win32_operatingsystem | select Caption, BuildNumber).Caption
$OS_Build=(Get-CimInstance  -class win32_operatingsystem | select Caption, BuildNumber).BuildNumber

$model=(Get-CimInstance -ClassName Win32_ComputerSystem |select Model).Model
$CPU=(Get-CimInstance -ClassName Win32_Processor ).Name
$RamData=Get-CimInstance win32_physicalmemory | select Manufacturer,Banklabel,Configuredclockspeed,Devicelocator,Capacity,Serialnumber | ConvertTo-Html -Fragment

Write-Host "Gathering Report Customization..." -ForegroundColor White

Write-Host "__________________________________" -ForegroundColor White

#Check for ReportHTML Module
$Mod = Get-Module -ListAvailable -Name "ReportHTML"

If ($null -eq $Mod)
{
	
	Write-Host "ReportHTML Module is not present, attempting to install it"
	
	Install-Module -Name ReportHTML -Force
	Import-Module ReportHTML -ErrorAction SilentlyContinue
}

#Array of default Security Groups
function New-Client_UserInformation()
{
  param ($var)


  $Client_UserInformation = new-object PSObject
  $Client_UserInformation | add-member -type NoteProperty -Name Client -Value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."CLIENT")
  $Client_UserInformation | add-member -type NoteProperty -Name Emplacement -Value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Emplacement")
  $Client_UserInformation | add-member -type NoteProperty -Name Technicien -Value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Technicien")
  $Client_UserInformation | add-member -type NoteProperty -Name User_Session -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."User_Session")
  $Client_UserInformation | add-member -type NoteProperty -Name MDP_Session -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."MDP_Session")
  $Client_UserInformation | add-member -type NoteProperty -Name User_Admin -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."User_Admin")
  $Client_UserInformation | add-member -type NoteProperty -Name MDP_ADMIN -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."MDP_ADMIN")
  $Client_UserInformation | add-member -type NoteProperty -Name Nom_de_L_Ordinateur -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Nom_de_L_Ordinateur")
  $Client_UserInformation | add-member -type NoteProperty -Name Hostname -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Hostname" )
  $Client_UserInformation | add-member -type NoteProperty -Name Workgroup -value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Workgroup")
  $Client_UserInformation | add-member -type NoteProperty -Name Date_Install -Value ((get-ItemProperty -Path "HKLM:\Software\PYLO\0")."Date_Install")
  return $Client_UserInformation
}
$Client_UserInformation=New-Client_UserInformation
function New-Computer_Info()
{
  param ($var)
  $computer_info_d=Get-ComputerInfo
  $Computer_Info = new-object PSObject
  $Computer_Info | add-member -type NoteProperty -Name Nom_Modele -Value $computer_info_d.CsModel
  $Computer_Info | add-member -type NoteProperty -Name Reference -Value $computer_info_d.CsSystemSKUNumber
  $Computer_Info | add-member -type NoteProperty -Name Numero_de_serie -Value $computer_info_d.BiosSeralNumber
  $Computer_Info | add-member -type NoteProperty -Name OS -Value $computer_info_d.OsName
  $Computer_Info | add-member -type NoteProperty -Name OS_Build -Value $computer_info_d.OsBuildNumber
  $Computer_Info | add-member -type NoteProperty -Name OS_Architecture -Value $computer_info_d.CsSystemType
  $Computer_Info | add-member -type NoteProperty -Name Ram -Value (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB)})
  $Computer_Info | add-member -type NoteProperty -Name TVID -Value (Get-TVID)
  $Computer_Info | add-member -type NoteProperty -Name Date_Install -Value $computer_info_d.WindowsInstallDateFromRegistry
  
  return $Computer_Info
}
$Computer_Info=New-Computer_Info
$computerRam=Get-WmiObject Win32_PhysicalMemory | select DeviceLocator, @{Name="Capacity";Expression={ "{0:N1} GB" -f ($_.Capacity / 1GB)}}, ConfiguredClockSpeed, ConfiguredVoltage,SerialNumber,Manufacturer 



$computerSystem = Get-CimInstance CIM_ComputerSystem
$computerBIOS = Get-CimInstance CIM_BIOSElement

$computerOs=Get-WmiObject win32_operatingsystem | select Caption, CSName, Version, @{Name="InstallDate";Expression={([WMI]'').ConvertToDateTime($_.InstallDate)}} , @{Name="LastBootUpTime";Expression={([WMI]'').ConvertToDateTime($_.LastBootUpTime)}}, @{Name="LocalDateTime";Expression={([WMI]'').ConvertToDateTime($_.LocalDateTime)}}, CurrentTimeZone, CountryCode, OSLanguage, SerialNumber, WindowsDirectory 
$computerCpu=Get-WmiObject Win32_Processor | select DeviceID, Name, Caption, Manufacturer, MaxClockSpeed, L2CacheSize, L2CacheSpeed, L3CacheSize, L3CacheSpeed 
$computerMainboard=Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer,Model, Name,SerialNumber,SKU,Version,Product


# Get HDDs
$driveType = @{
   2="Removable disk "
   3="Fixed local disk "
   4="Network disk "
   5="Compact disk "}
$Hdds = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | select DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} 
function Get-Monitore
{
<#
.SYNOPSIS
This powershell function gets information about the monitors attached to any computer. It uses EDID information provided by WMI. If this value is not specified it pulls the monitors of the computer that the script is being run on.

.DESCRIPTION
The function begins by looping through each computer specified. For each computer it gets a list of monitors.
It then gets all of the necessary data from each monitor object and converts and cleans the data and places it in a custom PSObject. It then adds
the data to an array. At the end the array is displayed.

.PARAMETER ComputerName
Use this to specify the computer(s) which you'd like to retrieve information about monitors from.

.EXAMPLE
PS C:/> Get-Monitor.ps1 -ComputerName MyComputer

Manufacturer Model SerialNumber AttachedComputer
------------ ----- ------------ ---------------
Acer Acer K272HUL T0SfADAFD MyComputer

.EXAMPLE
PS C:/> $Computers = @("Comp1","Comp2","Comp3")
PS C:/> Get-Monitor.ps1 -ComputerName $Computers

Manufacturer Model SerialNumber AttachedComputer
------------ ----- ------------ ----------------

#>

[CmdletBinding()]
PARAM (
[Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
[String[]]$ComputerName = $env:ComputerName
)

#List of Manufacture Codes that could be pulled from WMI and their respective full names. Used for translating later down.
$ManufacturerHash = @{
"AAC" = "AcerView";
"ACR" = "Acer";
"ACI" = " Asus";
"APP" = "Apple Computer";
"AUO" = "Asus";
"CMO" = "Acer";
"CPQ" = "Compaq";
"DEL" = "Dell";
"HWP" = "HP";
"LEN" = "Lenovo";
"SAN" = "Samsung";
"SAM" = "Samsung";
"SNY" = "Sony";
"SRC" = "Shamrock";
"SUN" = "Sun Microsystems";
"SEC" = "Hewlett-Packard";
"TAT" = "Tatung";
"TOS" = "Toshiba";
"TSB" = "Toshiba";
"VSC" = "ViewSonic";
"UNK" = "Unknown";
"_YV" = "Fujitsu";
}


#Takes each computer specified and runs the following code:
ForEach ($Computer in $ComputerName) {

#Grabs the Monitor objects from WMI
$Monitors = Get-WmiObject -Namespace "root\WMI" -Class "WMIMonitorID" -ComputerName $Computer -ErrorAction SilentlyContinue

#Creates an empty array to hold the data
$Monitor_Array = @()


#Takes each monitor object found and runs the following code:
ForEach ($Monitor in $Monitors) {

#Grabs respective data and converts it from ASCII encoding and removes any trailing ASCII null values
If ([System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName) -ne $null) {
$Mon_Model = ([System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName)).Replace("$([char]0x0000)","")
} else {
$Mon_Model = $null
}
$Mon_Serial_Number = ([System.Text.Encoding]::ASCII.GetString($Monitor.SerialNumberID)).Replace("$([char]0x0000)","")
$Mon_Attached_Computer = ($Monitor.PSComputerName).Replace("$([char]0x0000)","")
$Mon_Manufacturer = ([System.Text.Encoding]::ASCII.GetString($Monitor.ManufacturerName)).Replace("$([char]0x0000)","")


#Sets a friendly name based on the hash table above. If no entry found sets it to the original 3 character code
$Mon_Manufacturer_Friendly = $ManufacturerHash.$Mon_Manufacturer
If ($Mon_Manufacturer_Friendly -eq $null) {
$Mon_Manufacturer_Friendly = $Mon_Manufacturer
}

#Creates a custom monitor object and fills it with 4 NoteProperty members and the respective data
$Monitor_Obj = [PSCustomObject]@{
Manufacturer = $Mon_Manufacturer_Friendly
Model = $Mon_Model
SerialNumber = $Mon_Serial_Number
AttachedComputer = $Mon_Attached_Computer
}

#Appends the object to the array
$Monitor_Array += $Monitor_Obj

} #End ForEach Monitor

#Outputs the Array
$Monitor_Array

} #End ForEach Computer
}
function Get-MrMonitorInfo {

<#
.SYNOPSIS
    Retrieves information about the monitors connected to the specified system.
  
.DESCRIPTION
    Get-MrMonitorInfo is an advanced function that retrieves information about the monitors
    connected to the specified system.
  
.PARAMETER CimSession
    Specifies the CIM session to use for this function. Enter a variable that contains the CIM session or a command that
    creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see
    about_CimSessions.
  
.EXAMPLE
     Get-MrMonitorInfo
 
.EXAMPLE
     Get-MrMonitorInfo -CimSession (New-CimSession -ComputerName Server01, Server02)
  
.INPUTS
    None
  
.OUTPUTS
    Mr.MonitorInfo
  
.NOTES
    Author: Mike F Robbins
    Website: http://mikefrobbins.com
    Twitter: @mikefrobbins
#>

    [CmdletBinding()]
    [OutputType('Mr.MonitorInfo')]
    param (
        [Microsoft.Management.Infrastructure.CimSession[]]$CimSession
    )

    $Params = @{
        ErrorAction = 'SilentlyContinue'
        ErrorVariable = 'Problem'
    }

    if ($PSBoundParameters.CimSession) {
        $Params.CimSession = $CimSession
    }

    $ComputerInfo = Get-CimInstance @Params -ClassName Win32_ComputerSystem -Property Name, Manufacturer, Model
    $BIOS = Get-CimInstance @Params -ClassName Win32_BIOS -Property SerialNumber
    $Monitors = Get-CimInstance @Params -ClassName WmiMonitorID -Namespace root/WMI -Property ManufacturerName, UserFriendlyName, ProductCodeID, SerialNumberID, WeekOfManufacture, YearOfManufacture

    foreach ($Computer in $ComputerInfo) {
        
        foreach ($Monitor in $Monitors | Where-Object {-not $_.PSComputerName -or $_.PSComputerName -eq $Computer.Name}) {

            if (-not $PSBoundParameters.CimSession) {
                
                Write-Verbose -Message "Running against the local system. Setting value for PSComputerName (a read-only property) to $env:COMPUTERNAME."
                ($BIOS.GetType().GetField('_CimSessionComputerName','static,nonpublic,instance')).SetValue($BIOS,$Computer.Name)

            }

            [pscustomobject]@{
                ComputerName = $Computer.Name
               # ComputerManufacturer = $Computer.Manufacturer
               # ComputerModel = $Computer.Model
               # ComputerSerial = ($BIOS | Where-Object PSComputerName -eq $Computer.Name).SerialNumber
                MonitorManufacturer = -join $Monitor.ManufacturerName.ForEach({[char]$_})
                MonitorModel = -join $Monitor.UserFriendlyName.ForEach({[char]$_})
                ProductCode = -join $Monitor.ProductCodeID.ForEach({[char]$_})
                MonitorSerial = -join $Monitor.SerialNumberID.ForEach({[char]$_})
                MonitorManufactureWeek = $Monitor.WeekOfManufacture
                MonitorManufactureYear = $Monitor.YearOfManufacture
               # PSTypeName = 'Mr.MonitorInfo'
            }
                
        }
    
    }
    
    foreach ($p in $Problem) {
        Write-Warning -Message "An error occurred on $($p.OriginInfo). $($p.Exception.Message)"
    }

}
 

##-----------------------Fiche de prep Checking-----------------------------------##
function Prep_Phase1
{
    function Test_Admin
    {
    $username = 'ADMIN'
    $password = 'Kon!B091'

    $computer = $env:COMPUTERNAME

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',
    $computer)
    return $obj.ValidateCredentials($username, $password)
    }
     function test_WOL
     {
        $nic = Get-NetAdapter | ? {($_.MediaConnectionState -eq "Connected") -and (($_.name -match "Ethernet") -or ($_.name -match "local area connection"))}
        $nicPowerWake = Get-WmiObject MSPower_DeviceWakeEnable -Namespace root\wmi | where {$_.instancename -match [regex]::escape($nic.PNPDeviceID) }
        If ($nicPowerWake.Enable -eq $true)
        {
            # All good here
            $Test_WOL= $true
            $nicMagicPacket = Get-WmiObject MSNdis_DeviceWakeOnMagicPacketOnly -Namespace root\wmi | where {$_.instancename -match [regex]::escape($nic.PNPDeviceID) }
            If ($nicMagicPacket.EnableWakeOnMagicPacketOnly -eq $true)
            {
                # All good here
                $FindEEELinkAd = Get-ChildItem "hklm:\SYSTEM\ControlSet001\Control\Class" -Recurse -ErrorAction SilentlyContinue | % {Get-ItemProperty $_.pspath} -ErrorAction SilentlyContinue | ? {$_.EEELinkAdvertisement} -ErrorAction SilentlyContinue
                If ($FindEEELinkAd.EEELinkAdvertisement -eq 1)
                {
                    Set-ItemProperty -Path $FindEEELinkAd.PSPath -Name EEELinkAdvertisement -Value 0
                    # Check again
                    $FindEEELinkAd = Get-ChildItem "hklm:\SYSTEM\ControlSet001\Control\Class" -Recurse -ErrorAction SilentlyContinue | % {Get-ItemProperty $_.pspath} | ? {$_.EEELinkAdvertisement}
                    If ($FindEEELinkAd.EEELinkAdvertisement -eq 1)
                    {
                        write-output "$($env:computername) - ERROR - EEELinkAdvertisement set to $($FindEEELinkAd.EEELinkAdvertisement)"
                         return $false
                    }
                    Else
                    {
                        write-output "$($env:computername) - SUCCESS - EEELinkAdvertisement set to $($FindEEELinkAd.EEELinkAdvertisement)"
                         return $false
                    }
                }
                Else
                {
                    write-output "EEELinkAdvertisement is already turned OFF"
                    $FindHiberbootEnabled = Get-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Session?Manager\Power" -ErrorAction SilentlyContinue
                    If ($FindHiberbootEnabled.HiberbootEnabled -eq 1)
                    {
                        write-output "HiberbootEnabled is Enabled. Setting to DISABLED..."
                        Set-ItemProperty -Path $FindHiberbootEnabled.PSPath -Name "HiberbootEnabled" -Value 0 -Type DWORD -Force | Out-Null
                        return $true
                    }
                    else 
                    {
                        return $true
                    }

                }

            }
            else 
            {
                return $false
            }
        }
        else
        {
            return  $false
        }

            }

    function Test_Boot_Failure
    {
    ([string](bcdedit /enum All /v |Select-string bootstatuspolicy )) -match "IgnoreShutdownFailures"
    }
    function test_UAC
    {
    
     return (((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")."ConsentPromptBehaviorAdmin" -eq 0) -and ((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System").PromptOnSecureDesktop -eq 0))
     #((Get-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system")."EnableLUA" -eq 0 )
    }

    function test_USB_2_3
    {
    
     
     #((Get-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system")."EnableLUA" -eq 0 )
     $var=$false
     $hubs = Get-WmiObject Win32_USBHub
     $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi
        foreach ($p in $powerMgmt)
        {
          $IN = $p.InstanceName.ToUpper()
          foreach ($h in $hubs)
          {
            $PNPDI = $h.PNPDeviceID
                        if ($IN -like "*$PNPDI*")
                        {
                             $var= $var -or $p.enable 
                            
                        }
          }
        }

        return !$var;

    }

    function test_ipv6
    {
    
      #disable IPV6
        $nic = get-netadapter
        $var = $true
        #Disable-NetAdapterBinding
        get-netadapter|%{$var=(((Get-NetAdapterBinding -Name $_.name -ComponentID ms_tcpip6).Enabled -eq $false) -and $var) }
        return $var;

    }


    function TeamViewerInstalled
    {
        return (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "TeamViewer" }  | %{ if( $_ -eq $null) {return $false } else { return $_.Version }});
    }
    

    function Choco_Installed
    {
        return !((Get-Command -Name  choco) -eq $null)
    }

    $Test_Admin=Test_Admin
    $Test_ComputerName=$env:COMPUTERNAME -eq (Get-Content -path "C:\Pylo\data.txt" | Select-Object -Skip 7 -First 1)
    function New-Prep_Phase1_data
    {
    
        [CmdletBinding()]
        PARAM (
	        [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter URL or UNC path to Company Logo")]
	        [String]$ComputerName = $env:COMPUTERNAME,
	        [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter URL or UNC path for Side Logo")]
	        [String]$Nom_du_test = "Default_Test",
	        [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter desired title for report")]
	        [bool]$Valeur_Prep = ""
        )
      $Prep_Phase1_d = new-object PSObject
      $Prep_Phase1_d | add-member -type NoteProperty -Name Nom_Poste -Value $env:COMPUTERNAME
      $Prep_Phase1_d | add-member -type NoteProperty -Name TEST -Value $Nom_du_test
      $Prep_Phase1_d | add-member -type NoteProperty -Name Phase_Init -Value $Valeur_Prep
      $Prep_Phase1_d | add-member -type NoteProperty -Name Phase_User -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_1 -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_2 -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_3 -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_4 -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_5 -Value ""
      $Prep_Phase1_d | add-member -type NoteProperty -Name Maitenance_Mois_6 -Value ""
      return $Prep_Phase1_d;
    }
    Function test_DebloatAll {
    $WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.XboxGameCallableUI|Microsoft.XboxGamingOverlay|Microsoft.Xbox.TCUI|Microsoft.XboxGamingOverlay|Microsoft.XboxIdentityProvider|Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|`
    Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller|WindSynthBerry|MIDIBerry|Slack'
    #NonRemovable Apps that where getting attempted and the system would reject the uninstall, speeds up debloat and prevents 'initalizing' overlay when removing apps
    $NonRemovable = '1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|`
    Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.MicrosoftEdge|Microsoft.PPIProjection|Microsoft.Win32WebViewHost|Microsoft.Windows.Apprep.ChxApp|`
    Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|`
    Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|`
    Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|Windows.CBSPreview|windows.immersivecontrolpanel|Windows.PrintDialog|Microsoft.VCLibs.140.00|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0|*Nvidia*'
    return ((Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} ) -eq $null) -and ((Get-AppxPackage | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} )-eq $null ) -and ((Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps -and $_.PackageName -NotMatch $NonRemovable} | Remove-AppxProvisionedPackage -Online) -eq $null);
    }

    $Table = New-Object 'System.Collections.Generic.List[System.Object]'


    
    
    
    
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Test Admin" -Valeur_Prep (Test_Admin)) ) # test Admin


    $Table.Add( (New-Prep_Phase1_data  -Nom_du_test "Test hostname" -Valeur_Prep ($env:COMPUTERNAME -eq "")) ) # test hostname


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test WOL" -Valeur_Prep (test_WOL)) ) # test WOL


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test BootFailure" -Valeur_Prep (Test_Boot_Failure)) ) #Test_Boot_Failure


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test UAC" -Valeur_Prep (test_UAC)) ) # test test_UAC


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test IPV6 Desavtiver" -Valeur_Prep (test_ipv6)) ) # test_ipv6


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test USB 2 et 3 power off" -Valeur_Prep (test_USB_2_3)) ) # test_USB_2


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test Teamviewe Installer" -Valeur_Prep (TeamViewerInstalled)) ) # TeamViewer_Installed


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test TVID" -Valeur_Prep (Get-TVID)) ) # TVID


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "test Choco" -Valeur_Prep (Choco_Installed)) ) # Choco_Installed


    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "WSMAN listen actif" -Valeur_Prep (!($WSMAN_Test=(Get-NetTCPConnection | Where-Object -Property LocalPort -eq 5985 ) -eq $null)))  ) # WSMAN_Listener
    


    $wsman_thrust=((get-Item WSMan:\localhost\Client\TrustedHosts).value -eq '*')
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "WSMAN Thrusted host" -Valeur_Prep $wsman_thrust) ) # WSMAN Thrusted Host


    $testHP=((Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "HP" }).count -eq 0)
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Debloat HP" -Valeur_Prep $testHP) ) # remove bloat HP



    $testDebloat= ( (test_DebloatAll) -eq $null)
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Debloat Windows" -Valeur_Prep $testDebloat) ) # remove bloat Windows
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Test Ribbons Screensaver" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Control Panel\Desktop").'scrnsave.exe' -eq  "c:\windows\system32\Ribbons.scr"))  ) # Test scrnsave_Ribbons
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Test ScreenSaver Actif" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Control Panel\Desktop").ScreenSaveActive -eq 0))  ) # Test ScreenSaveActive
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Test ScreenSaveTimeout" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Control Panel\Desktop").ScreenSaveTimeOut -eq 0) ) ) # Test ScreenSaveTimeOut

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "No NoLockScreen" -Valeur_Prep ((get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")."NoLockScreen") -eq 1)  ) # Test Disable Lock screen

    
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Test Action Center retirer" -Valeur_Prep (( ((get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")."DisableNotificationCenter") -eq 1) -and ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications")."ToastEnabled" -eq 0)))  ) # Test Disable Action Center

    

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Dsiable lockScreen" -Valeur_Prep ((get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")."NoLockScreen" -eq 1)) ) # Test Disable Lock screen
    
    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")."SearchboxTaskbarMode" -eq 0) ) ) # Test Hide Search button / box

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre taskview retirer" -Valeur_Prep (( get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")."ShowTaskViewButton" -eq 0)) ) # Test Hide Task View button

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre title retirer" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")."TaskbarGlomLevel" -eq 0)) ) # Test Hide titles in taskbar

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre tray icon retirer" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced").EnableAutoTray -eq $null)) ) # Test Hide tray icons as needed

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "voir les extension" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")."HideFileExt" -eq 0)) ) # Test  Show known file extensions

    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Voir fichier cacher" -Valeur_Prep ((get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")."Hidden" -eq 1)) ) # Test Show hidden files

#    $Table.Add( (New-Prep_Phase1_data -Nom_du_test "Script mapping pour tous" -Valeur_Prep ()) ) # Test Script Mapping for all user



<#
# Show Computer shortcut on desktop
 $TextBox_Logs.Text+= "Showing Computer shortcut on desktop..."
 get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box
 
# Add Documents icon to computer namespace
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box

# Add Downloads icon to computer namespace
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box

# Add Music icon to computer namespace
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box

# Add Pictures icon to computer namespace
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box

# Add Videos icon to computer namespace
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
 get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
 $Table.Add( (New-Prep_Phase1_data -Nom_du_test "barre recherche retirer" -Valeur_Prep () ) ) # Test Hide Search button / box
 #>

  <#
  $Prep_Phase1_d | add-member -type NoteProperty -Name Test_Admin -Value 
  $Prep_Phase1_d | add-member -type NoteProperty -Name test_WOL -Value (test_WOL)
  $Prep_Phase1_d | add-member -type NoteProperty -Name Test_Boot_Failure -Value (Test_Boot_Failure)
  $Prep_Phase1_d | add-member -type NoteProperty -Name test_UAC -Value (test_UAC)
  $Prep_Phase1_d | add-member -type NoteProperty -Name test_ipv6 -Value (test_ipv6)
  $Prep_Phase1_d | add-member -type NoteProperty -Name test_USB_2-3 -Value (test_USB_2_3)
  $Prep_Phase1_d | add-member -type NoteProperty -Name TeamViewer_Installed -Value (TeamViewerInstalled)
  $Prep_Phase1_d | add-member -type NoteProperty -Name TVID -Value (Get-TVID )
  $Prep_Phase1_d | add-member -type NoteProperty -Name Choco_Installed -Value (Choco_Installed)
  #>
  New-Item -Path "HKLM:\Software\PYLO" -Name "1" –Force
  $Table |% { Set-ItemProperty -Path "HKLM:\Software\PYLO\1" -Name $_.TEST -Value $_.Phase_Init}
  return $Table

}

$Prep_Phase1_d=Prep_Phase1
$AllInstall_Programms= Get-SoftwareV1
#Get all users right away. Instead of doing several lookups, we will use this object to look up all the information needed.

<###########################
         Dashboard
############################>

Write-Host "Working on Dashboard Report..." -ForegroundColor Green

Write-Host "Done!" -ForegroundColor White

$tabarray = @('Inventaire','Prep-Check', "Audit")

Write-Host "Compiling Report..." -ForegroundColor Green

#Dashboard Report
$FinalReport = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalReport.Add($(Get-HTMLOpenPage -TitleText $ReportTitle -LeftLogoString $CompanyLogo -RightLogoString $RightLogo))
$FinalReport.Add($(Get-HTMLTabHeader -TabNames $tabarray))
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $tabarray[0] -TabHeading ("Report: " + (Get-Date -Format dd-MM-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Client et Installation"))
$FinalReport.Add($(Get-HTMLContentTable $Client_UserInformation))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Caracteristique systeme"))
$FinalReport.Add($(Get-HTMLContentTable $Computer_Info))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Caracteristique HDD, Ram"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Ram Info'))
$FinalReport.Add($(Get-HTMLContentDataTable $computerRam -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Disque dure'))
$FinalReport.Add($(Get-HTMLContentDataTable $Hdds -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))
#---------------------------------------------------

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "CPU and Carte mere"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "CPU"))
$FinalReport.Add($(Get-HTMLContentDataTable $computerCpu -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Carte mere'))
$FinalReport.Add($(Get-HTMLContentDataTable $computerMainboard -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "GPU et Ecran"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Ecran"))
$FinalReport.Add($(Get-HTMLContentDataTable ((Get-MrMonitorInfo)) -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Carte graphique'))
$FinalReport.Add($(Get-HTMLContentDataTable (Get-CimInstance CIM_VideoController | Select-Object -Property SystemName,AdapterCompatibility,Description, VideoProcessor,DriverVersion,DriverDate,VideoModeDescription,@{Name="AdapterRAM";Expression={ "{0:N1} GB" -f ($_.AdapterRAM / 1GB)}})  -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLTabContentClose))




#Groups Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $tabarray[1] -TabHeading ("Report: " + (Get-Date -Format dd-MM-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Client Overview"))
$FinalReport.Add($(Get-HTMLContentTable $Client_UserInformation -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Phase 1 Check'))
$FinalReport.Add($(Get-HTMLContentTable $Prep_Phase1_d -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLTabContentClose))


$FinalReport.Add($(Get-HTMLClosePage))

$FinalReport=$FinalReport -replace "False", '<FONT color="red"> ECHEC </FONT> '
$FinalReport=$FinalReport -replace "True", '<FONT color="green"> Succes </FONT> '
$Day = (Get-Date).Day
$Month = (Get-Date).Month
$Year = (Get-Date).Year
$Hour = (Get-Date).Hour
$Minute = (Get-Date).Minute

$ReportName = ("$Year-$Month-$day-$Hour-$Minute-$env:COMPUTERNAME")
mkdir -Path "C:\Pylo" -ErrorAction SilentlyContinue

Save-HTMLReport -ReportContent $FinalReport -ShowReport -ReportName "$ReportName.html" -ReportPath "C:\Pylo" 
<#
$password = ConvertTo-SecureString 'autoPYLOKon!B091' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ('autoPYLO', $password)
$ClientVar=$CLIENT_TEXT.Text

$SessionVar=New-SSHSession  -AcceptKey   -ComputerName "manage.PYLO.info" -Credential $credential
Invoke-SSHCommand -Index $SessionVar.SessionId -Command "mkdir ./public/Rapport/$ClientVar"
#Set-SCPFile -AcceptKey $true -LocalFile "C:\Pylo\$ReportName.html" -RemotePath "./public/Rapport/$ClientVar/" -ComputerName "manage.PYLO.info" -Credential $credential
#>

Add-Type -AssemblyName System.speech
$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speak.Volume = 100
$speak.Speak("Operation Completed")

$wshell = New-Object -ComObject Wscript.Shell

$wshell.Popup("Operation Completed",0,"Done",0x1)

#rm -Path "C:\Pylo\$ReportName.html" -Force
#rm -Path "C:\Scripts\*" -Force
 
    
  })

#Write your logic code here

[void]$Pylo_Prep_Automatisation.ShowDialog()

<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    ONIBO_PREP_AUTO

#>


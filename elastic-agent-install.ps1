# Requires: ActiveDirectory and GroupPolicy Modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# --- Configuration ---
$GpoName = "Deploy Elastic Agent"
$TargetOU = (Get-ADDomain).ComputersContainer

# Elastic Agent Variables
$AgentVersion = "8.10.4"
$FleetUrl = "https://192.168.10.100:8220"
$EnrollmentToken = "c19UcUhaZ0I2Rkd1YjJFRnAtV186MGc4NXl0U1FRakNRUmpBQVRfd3lrZw=="
$DownloadUrl = "http://192.168.10.22/elastic-agent-$AgentVersion-windows-x86_64.zip"

# Deployment Script Content
$ScriptContent = @"
# Elastic Agent Deployment Script
\$ProgressPreference = 'SilentlyContinue'
\$AgentVersion = '$AgentVersion'
\$DownloadUrl = '$DownloadUrl'
\$FleetUrl = '$FleetUrl'
\$EnrollmentToken = '$EnrollmentToken'
\$DestinationPath = 'C:\Temp\ElasticAgentInstall'
\$LogFile = 'C:\Windows\Temp\ElasticAgentInstall.log'

Function Write-Log { Param(\$Message) Add-Content -Path \$LogFile -Value "[\$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] \$Message" }

Write-Log "Starting Elastic Agent deployment."

try {
    \$AgentService = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
    if (\$AgentService -and \$AgentService.Status -eq 'Running') { Write-Log "Agent already running. Exiting."; exit 0 }
} catch { Write-Log "Service check failed: \$($_.Exception.Message)" }

if (-not (Test-Path \$DestinationPath)) { New-Item -Path \$DestinationPath -ItemType Directory -Force | Out-Null }

\$ZipPath = Join-Path \$DestinationPath "elastic-agent-\$AgentVersion-windows-x86_64.zip"
Invoke-WebRequest -Uri \$DownloadUrl -OutFile \$ZipPath -ErrorAction Stop
Expand-Archive -Path \$ZipPath -DestinationPath \$DestinationPath -Force

\$AgentDir = Join-Path \$DestinationPath "elastic-agent-\$AgentVersion-windows-x86_64"
Set-Location \$AgentDir

.\elastic-agent.exe install --url=\$FleetUrl --enrollment-token=\$EnrollmentToken -i -f | ForEach-Object { Write-Log \$_ }

Start-Sleep 30
\$Service = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if (\$Service.Status -eq 'Running') { Write-Log "Elastic Agent installed and running." } else { Write-Log "Agent installation incomplete or failed." }

Set-Location C:\
Remove-Item -Path \$DestinationPath -Recurse -Force -ErrorAction SilentlyContinue
"@

# --- GPO Creation and Linking ---
$GPO = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

if (-not $GPO) {
    $GPO = New-GPO -Name $GpoName -ErrorAction Stop
    Write-Host "Created GPO: $GpoName"
}

# Link GPO if not already linked
$Linked = (Get-GPOReport -Name $GpoName -ReportType Xml | 
    Select-Xml "//Links/Link/SOMPath").Node.InnerText -contains $TargetOU

if (-not $Linked) {
    New-GPLink -Name $GpoName -Target $TargetOU -Enforced $true
    Write-Host "Linked GPO to $TargetOU"
}

# --- Save Startup Script to SYSVOL ---
$Domain = (Get-ADDomain).DNSRoot
$GPOPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($GPO.Id)}\Machine\Scripts\Startup"
if (-not (Test-Path $GPOPath)) { New-Item -Path $GPOPath -ItemType Directory -Force | Out-Null }

$ScriptName = "Deploy-ElasticAgent.ps1"
$ScriptFullPath = Join-Path $GPOPath $ScriptName
$ScriptContent | Set-Content -Path $ScriptFullPath -Encoding UTF8

# --- Configure GPO Startup Script ---
$StartupScripts = Get-GPStartupScript -Name $GpoName -ErrorAction SilentlyContinue
if ($StartupScripts.Script -contains $ScriptName) {
    Write-Host "Startup script already configured. Skipping."
} else {
    Add-GPStartupScript -Name $GpoName -Script $ScriptName -ScriptType PowerShell
    Write-Host "Configured startup script: $ScriptName"
}

# --- Force GPUpdate on All Computers ---
Write-Host "Forcing gpupdate /force on all domain computers..."

$Computers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name

foreach ($Computer in $Computers) {
    try {
        Invoke-GPUpdate -Computer $Computer -Force -RandomDelayInMinutes 0 -ErrorAction Stop
        Write-Host "gpupdate triggered on $Computer"
    } catch {
        Write-Host "Could not update $Computer: $($_.Exception.Message)"
    }
}

Write-Host "Elastic Agent GPO deployment complete. Machines will apply the policy immediately."

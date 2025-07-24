# Elastic
#(get-service -name "Elastic Agent").Status -eq "Running"


$Computers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name

foreach ($Computer in $Computers) {
    Write-Host "Starting on " $Computer
    new-PSSession -ComputerName $Computer
    Invoke-Command -computername $Computer -scriptblock { 
    $AgentVersion = '8.10.4'
    $fleetUrl = 'https://192.168.10.100:8220'
    $enrollmenttoken = 'c19UcUhaz0i2rkd1yjJFrnAtv186mGc4Nxl0u1frajnrumpBQvRfd3lrZw=='
    $DownloadUrl = "http://192.168.10.22/elastic-agent-8.10.4-windows-x86_64.zip"

    # This part would be run ON THE REMOTE MACHINE after you've entered the session
    # Define paths on the remote machine
    $destinationpath = 'C:\Temp\elasticAgentInstall'
    $ZipFileName = "elastic-agent-$AgentVersion-windows-x86-64.zip" # Correct filename for the zip
    $ZipPath = Join-Path $destinationpath $ZipFileName
    $AgentDirName = "elastic-agent-$AgentVersion-windows-x86-64" # Correct folder name after unzip
    $AgentDir = Join-Path $destinationpath $AgentDirName

    # Create the destination directory if it doesn't exist
    New-Item -ItemType Directory -Path $destinationpath -Force

    Write-Host "Downloading Elastic Agent from $($DownloadUrl) to $($ZipPath)..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -ErrorAction Stop

    Write-Host "Expanding archive $($ZipPath) to $($destinationpath)..."
    Expand-Archive -Path $ZipPath -DestinationPath $destinationpath -Force

    Write-Host "Setting current location to $($AgentDir)..."
    Set-Location "C:\Temp\elasticAgentInstall\elastic-agent-8.10.4-windows-x86_64"

    Write-Host "Installing Elastic Agent..."
    # Corrected arguments: Removed unnecessary backslash before $fleeturl
    .\elastic-agent.exe install --url=https://192.168.10.100:8220 --enrollment-token=c19UcUhaZ0I2Rkd1YjJFRnAtV186MGc4NXl0U1FRakNRUmpBQVRfd3lrZw== -i -f
    
    
    (get-service -name "Elastic Agent").Status -eq "Running"
    }
    remove-pssession -ComputerName $Computer
    
    }

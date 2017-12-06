Function Initialize-ChefClient {
    <#
        .SYNOPSIS
            Install Chef agent on remote servers.

        .DESCRIPTION
            Initiates remote PSSession on specified servers, downloads Chef agent, installs agent,
            and initiates first run. 

        .PARAMETER Name
            $ComputerName
        
        .EXAMPLE
            Initialize-ChefClient -ComputerName server1.domain.com -Environment 'QA' -verbose
        
		.EXAMPLE
            (Get-ADComputer -Filter {Name -like 'sjcd1pw*'}).DNSHostName | Initialize-ChefClient -Environment Production -Verbose -Runlist "'recipe[windows],recipe[windows::sccm_client_IAD]'"
  #>

    [CmdletBinding()]
    [OutputType()]
    Param (
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Runlist,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Production", "QA", "Staging", "Development")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Environment,

        [Parameter()]
        [PsCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    Begin {
 
        # Configure required variables

        $uri = 'https://packages.chef.io/files/current/chef/13.6.26/windows/2016/chef-client-13.6.26-1-x64.msi'
        $ChefAgent = $uri.Split('/')[-1]
        $ChefClientRB = 'client.rb'
        $ChefClientCert = 'client.pem'
        $ChefValidator = 'validation.pem'
        $ChefCert = 'chef_server.crt'
        $ChefLocalPath = "$env:SystemDrive\chef"
        $ChefLogPath = "$env:SystemDrive\chef\log"
        $ChefCertPath = "$env:SystemDrive\chef\trusted_certs"
        $LocalPath = "$env:SystemDrive\Install"
        $LogPath = "$env:SystemDrive\logs\ChefAgent_Install"
        $LogFile = (Get-Date -Format yyyy_MM_dd) + "_ChefAgent_Install.log"

        $ClientRBString = @'
log_level  :info
log_location  "C:/chef/log/client.log"
client_key "C:/chef/client.pem"
chef_server_url  "[your chef server url]"
validation_client_name  "validator"
validation_key  "C:/chef/validation.pem"
no_lazy_load :true

ohai.plugin_path << "C:/chef/ohai_plugins"
# ohai.hints_path << "C:/chef/ohai/hints"
ohai.disabled_plugins = [:Passwd,:Group]

# Do not crash if a handler is missing / not installed yet
begin
  rescue NameError => e
  Chef::Log.error e
end
'@

        $ChefValidatorString = @'
-----BEGIN RSA PRIVATE KEY-----
[Your validator cert]
-----END RSA PRIVATE KEY-----
'@

        $ChefCertString = @'
-----BEGIN CERTIFICATE-----
[Your chef server cert]
-----END CERTIFICATE-----
'@

        #Define ScriptBlock for data collection

        $ScriptBlock = {

            # Check for existing install

            $Apps64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' 
            $Apps32 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            $Apps = $Apps64 + $Apps32                                                 
            
            if ($Apps | Where-Object DisplayName -like 'Chef Client*') {
                Write-Verbose "Chef agent already installed on client $env:COMPUTERNAME"
            } 
            else {
                try {    
                    if (-not (Test-Path $LocalPath\$ChefAgent)) {
                        New-Item -ItemType Directory -Path $LocalPath -Force |
                        Out-Null
                        Invoke-WebRequest -Uri $uri -OutFile $LocalPath\$ChefAgent -ErrorAction Stop
                    }
                }
                catch {
                    $Message = (Get-Date -Format HH:mm:ss).ToString() + " : Unable to download $ChefAgent from $uri ; $_"
                    Write-Verbose $Message
                    $Message| Out-File $LogPath\$LogFile -Append
                    break
                }

                # Run msiexec to install agent msi

                Write-Verbose "Installing Chef agent on client $env:COMPUTERNAME"
                Write-Verbose "LogFile : $LogPath\$LogFile"

                New-Item -ItemType 'File' -Path $ChefLocalPath\$ChefClientRB -Value $ClientRBString -Force -ErrorAction Stop |
                Out-Null
                $Client_Install = Start-Process `
                    -FilePath "$env:SystemRoot\system32\msiexec.exe" `
                    -Wait `
                    -NoNewWindow `
                    -PassThru `
                    -ArgumentList "/qn /i $LocalPath\$ChefAgent /L*V+ $LogPath\$LogFile"

                if ($Client_Install.ExitCode -ne 0) {
                    Write-Verbose "Failed to install $ChefAgent ; $_ "
                    break
                } 
                else {
                    Write-Verbose "Chef Client has successfully installed.."
                }
            }

            # Run chef-client
                
            $ClientRunParams = @{
                ErrorAction = 'Stop'
            }
            
            try {
                if (-not (Test-Path $ChefLocalPath\$ChefClientRB)) {
                    New-Item -ItemType 'File' -Path $ChefLocalPath\$ChefClientRB -Value $ClientRBString -Force -ErrorAction Stop |
                    Out-Null
                }
                if (-not (Test-Path $ChefLocalPath\$ChefClientCert)) {
                    $ClientRunParams.Add('Runlist', 'windows')
                }
                Invoke-ChefClientRun @ClientRunParams
                Write-Verbose "Chef client converged on $env:COMPUTERNAME"
            } 
            catch {
                
                # Write failed chef-client converge to event log

                if (-not([System.Diagnostics.EventLog]::SourceExists('self-bootstrap'))) {
                    New-EventLog –LogName 'Application' –Source 'self-bootstrap' 
                }
                Write-EventLog –LogName 'Application' –Source 'self-bootstrap' -EntryType 'Error' -EventId '1' -Message 'Failed to converge chef client'
                Write-Verbose "Chef client failed to converged on $env:COMPUTERNAME"

                                
                # Create directory structure and chef config files
                                        
                Write-Verbose "Reseting chef client on $env:COMPUTERNAME"
                
                if (-not (Test-Path $LocalPath)) {
                    New-Item -ItemType Directory -Path $LocalPath -Force | Out-Null
                }
                if (-not (Test-Path $LogPath)) {
                    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
                }
                if (-not (Test-Path $ChefLogPath)) {
                    New-Item -ItemType Directory -Path $ChefLogPath -Force | Out-Null
                }
                if (-not (Test-Path $ChefLocalPath)) {
                    New-Item -ItemType Directory -Path $ChefLocalPath -Force | Out-Null
                }
                if (-not (Test-Path $ChefCertPath)) {
                    New-Item -ItemType Directory -Path $ChefCertPath -Force | Out-Null
                }
                New-Item -ItemType 'File' -Path $ChefLocalPath\$ChefClientRB -Value $ClientRBString -Force -ErrorAction Stop | Out-Null
                New-Item -ItemType 'File' -Path $ChefLocalPath\$ChefValidator -Value $ChefValidatorString -Force -ErrorAction Stop | Out-Null
                New-Item -ItemType 'File' -Path $ChefCertPath\$ChefCert -Value $ChefCertString -Force -ErrorAction Stop | Out-Null

                # If node has been failing for 3 days, attempt to re-bootstrap

                $FilterHashTable = @{
                    LogName   = 'Application'
                    ProviderName = 'self-bootstrap'
                    ID        = '1'
                    StartTime = (Get-Date).AddHours(-73)
                }
                if ((Get-WinEvent -FilterHashtable $FilterHashTable).Count -ge '12') {
                    if (Test-Path -Path $ChefLocalPath\client.pem) {
                        $NewName = (Get-Date -Format yyyy_MM_dd) + "_$ChefClientCert"
                        Rename-Item -Path $ChefLocalPath\$ChefClientCert -NewName $NewName -Force
                    }
                    $ClientRunParams.Add('Runlist', 'windows')
                }
                try {
                    Invoke-ChefClientRun @ClientRunParams
                    Write-Verbose "Chef client converged on $env:COMPUTERNAME"
                } 
                catch {
                    Write-Warning 'Unable to converge chef client.'
                    break
                }
            }
        }

        # Create logging directory

        if (-not (Test-Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }
    }

    Process {

        foreach ($Computer in $ComputerName) {

            # Run code on target server

            Write-Verbose "Initializing chef client on node $Computer, check logs for details"
            Invoke-Command -ScriptBlock $ScriptBlock
        }
    }

    End {}
}

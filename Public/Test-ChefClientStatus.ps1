Function Test-ChefClientStatus {
    <#
        .SYNOPSIS
            Check status of chef-client

        .DESCRIPTION
            Checks eventlog for successful chef client runs.
            Returns Boolean value
              'true' = success logged in last 3 hours
              'false' = no successes logged in last 3 hour

        .PARAMETER Name
            ComputerName
        
        .EXAMPLE
            Test-ChefClientStatus
        
		.EXAMPLE
            Test-ChefClientStatus -ComputerName 'iadd1pwtstap001' -Credential 'admin@domain.local'
			
        .EXAMPLE
            Get-ADComputer | Test-ChefClientStatus
  #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [PsCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    Begin {

        #Define ScriptBlock for data collection

        $ScriptBlock = {

            $ChefLocalPath = "$env:SystemDrive\chef"
            $FilterHashTable = @{
                LogName   = 'Application'
                ID        = '10002'
                StartTime = (Get-Date).AddHours(-3)
            }            
 
            # Check for successful event log entries
         

            try {
                [void](Get-WinEvent -FilterHashtable $FilterHashTable -OutVariable 'Event' -ErrorAction Stop)
            } catch {
                $Event = $false
            }
            $Client_Cert = Test-Path "$ChefLocalPath\client.pem" -ErrorAction Stop
            $Client_RB = Test-Path "$ChefLocalPath\client.rb" -ErrorAction Stop
            if (($Event) -and ($Client_Cert) -and ($Client_RB)) {
                Write-Output $true
            } else {
                Write-Output $false
            }
        }
    }

    Process {
        
        foreach ($Computer in $ComputerName) {
        
            # Build Hash to be used for passing parameters to Invoke-Command commandlet

            $CommandParams = @{
                ScriptBlock = $ScriptBlock
                ErrorAction = 'Stop'
            }
        
            # Add optional parameters to hash

            if (($Computer -notlike "$env:COMPUTERNAME*") -and ($Computer -notlike 'localhost')) {
                $CommandParams.Add('ComputerName', $Computer)
            } 

            # Run ScriptBlock

            try {
                Invoke-Command @CommandParams
            } catch {
                # Write-Error $_
            }
        }
    }

    End {}
}

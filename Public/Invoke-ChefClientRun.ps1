Function Invoke-ChefClientRun {
    <#
        .SYNOPSIS
            ####

        .DESCRIPTION
            ####

        .PARAMETER Name
            ####
        
        .EXAMPLE
            ####
        
		.EXAMPLE
            ####
			
        .EXAMPLE
            ####
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

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Runlist,

        [Parameter(
            # Mandatory=$true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Production", "QA", "Staging", "Development")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Environment
    )

    Begin {
        $OpscodeDir = "$env:SystemDrive\opscode\chef\bin"
    }
    Process {

        # Run chef-client

        if ($Runlist) {
            $Runlist_Arg = "-r $Runlist"
        }
        else {
            $Runlist_Arg = $null
        }
        if ($Environment) {
            $Environment_Arg = "-E $Environment"
        }
        else {
            $Environment_Arg = $null
        }
        
        Write-Verbose "Running chef-client $Environment_Arg $Runlist_Arg"

        $Client_Run_params = @{
            FilePath     = "$OpscodeDir\chef-client.bat"
            Wait         = $true
            NoNewWindow  = $true
            PassThru     = $true
            ErrorAction  = 'Stop'
            ArgumentList = "$Environment_Arg $Runlist_Arg"
        }
        
        $Client_Run = Start-Process @Client_Run_params

        if ($Client_Run.ExitCode -ne 0) {
            Write-Error 'Chef client has been installed, but node was not converged. Verify if node is listed on Chef server and try to run chef-client'
        }
        else {
            Write-Verbose 'Finished Running Chef Client. Your node is ready to go.'
        }

    }
    End {}
}

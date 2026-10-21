# Inspection never installs. Lifecycle mode is ONLY for an explicitly disposable runner.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Msi,
    [switch]$Inspect,
    [string]$UpgradeMsi
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# Windows Installer Automation, read-only database mode (0):
# https://learn.microsoft.com/en-us/windows/win32/msi/installer-opendatabase
function Read-MsiTable($Database, [string]$Table, [string[]]$Columns) {
    $names = ($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $view = $Database.OpenView('SELECT ' + $names + ' FROM `' + $Table + '`')
    try {
        # [void]: PS7's COM binder returns $null from void Automation methods; unvoided it leaks into the row pipeline.
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            try {
                $row = @{}
                for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = $record.StringData($i + 1) }
                [pscustomobject]$row
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function One-Row($Rows, [string]$Message) {
    $items = @($Rows)
    Assert-Test ($items.Count -eq 1) $Message
    return $items[0]
}

function Inspect-Msi([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $null
    try {
        $db = $installer.OpenDatabase($Path, 0)
        $properties = @{}
        Read-MsiTable $db Property @('Property', 'Value') | ForEach-Object { $properties[$_.Property] = $_.Value }
        Assert-Test ($properties['ALLUSERS'] -eq '1') 'MSI must be per-machine'
        Assert-Test ($properties['UpgradeCode'] -eq '{711087B1-08D6-505F-A81C-B348CDFA5D0F}') 'upgrade identity changed'
        Assert-Test ($properties['ProductVersion'] -match '^\d+\.\d+\.\d+$') 'MSI needs three version fields'
        $file = One-Row (Read-MsiTable $db File @('File', 'Component_', 'FileName')) 'expected one public payload file'
        Assert-Test ($file.File -eq 'EndpointExe' -and ($file.FileName -split '\|')[-1] -eq 'aegishook.exe') 'unexpected payload'
        $component = One-Row (Read-MsiTable $db Component @('Component', 'Directory_', 'Attributes', 'KeyPath')) 'expected one component'
        Assert-Test ($component.Component -eq $file.Component_ -and $component.KeyPath -eq $file.File -and $component.Directory_ -eq 'INSTALLFOLDER' -and (([int]$component.Attributes -band 256) -ne 0)) 'payload must be the x64 component key path'
        $directories = @(Read-MsiTable $db Directory @('Directory', 'Directory_Parent', 'DefaultDir'))
        $app = One-Row ($directories | Where-Object Directory -eq 'INSTALLFOLDER') 'missing install folder'
        Assert-Test ($app.Directory_Parent -eq 'ProgramFiles64Folder' -and ($app.DefaultDir -split '\|')[-1] -eq 'TG-Sentry') 'payload must be in Program Files\TG-Sentry'
        $service = One-Row (Read-MsiTable $db ServiceInstall @('Name', 'DisplayName', 'ServiceType', 'StartType', 'ErrorControl', 'StartName', 'Arguments', 'Component_')) 'expected one service'
        Assert-Test ($service.Name -eq 'TGSentryEndpoint' -and $service.DisplayName -eq 'TG-Sentry Endpoint') 'service names differ from service_windows.go'
        Assert-Test ($service.ServiceType -eq '16' -and $service.StartType -eq '2' -and $service.StartName -eq 'LocalSystem' -and $service.Arguments -eq 'service' -and $service.Component_ -eq $component.Component) 'wrong service registration'
        Assert-Test (([int]$service.ErrorControl -band 32768) -ne 0) 'service install must be vital'
        $control = One-Row (Read-MsiTable $db ServiceControl @('Name', 'Event', 'Wait', 'Component_')) 'expected one service control'
        # ServiceControl Event bits: install start/stop + uninstall stop/delete.
        # https://learn.microsoft.com/en-us/windows/win32/msi/servicecontrol-table
        Assert-Test ($control.Name -eq $service.Name -and $control.Event -eq '163' -and $control.Wait -eq '1' -and $control.Component_ -eq $component.Component) 'wrong service lifecycle controls'
        $recovery = One-Row (Read-MsiTable $db MsiServiceConfigFailureActions @('Name', 'Event', 'ResetPeriod', 'Actions', 'DelayActions', 'Component_')) 'missing failure actions'
        Assert-Test ($recovery.Name -eq $service.Name -and $recovery.Event -eq '5' -and $recovery.ResetPeriod -eq '86400' -and $recovery.Actions -eq '1[~]1[~]1' -and $recovery.DelayActions -eq '5000[~]10000[~]30000' -and $recovery.Component_ -eq $component.Component) 'wrong 5/10/30s recovery schedule'
        $config = One-Row (Read-MsiTable $db MsiServiceConfig @('Name', 'Event', 'ConfigType', 'Argument', 'Component_')) 'missing non-crash failure configuration'
        Assert-Test ($config.Name -eq $service.Name -and $config.Event -eq '5' -and $config.ConfigType -eq '4' -and $config.Argument -eq '1' -and $config.Component_ -eq $component.Component) 'non-crash failure recovery must be enabled at install'
        $actions = @(Read-MsiTable $db CustomAction @('Action', 'Type', 'Source', 'Target'))
        $sequence = @(Read-MsiTable $db InstallExecuteSequence @('Action', 'Condition', 'Sequence'))
        $expected = @{
            CtlRollback = @('ctl rollback', (18 + 1024 + 2048 + 8192 + 256))
            CtlInstall = @('ctl system-install --no-commit', (18 + 1024 + 2048 + 8192))
            CtlCommit = @('ctl commit', (18 + 1024 + 2048 + 8192 + 512 + 64))
            CtlUninstall = @('ctl system-uninstall', (18 + 1024 + 2048 + 8192))
        }
        foreach ($name in $expected.Keys) {
            $action = One-Row ($actions | Where-Object Action -eq $name) "missing custom action $name"
            Assert-Test ($action.Source -eq 'EndpointExe' -and $action.Target -eq $expected[$name][0] -and [int]$action.Type -eq $expected[$name][1]) "wrong execution flags/command for $name"
            $entry = One-Row ($sequence | Where-Object Action -eq $name) "missing sequence for $name"
            $condition = 'NOT Installed'
            if ($name -eq 'CtlUninstall') { $condition = 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE' }
            Assert-Test ($entry.Condition -eq $condition) "unsafe condition for $name"
        }
        $order = @{}
        $sequence | ForEach-Object { $order[$_.Action] = [int]$_.Sequence }
        Assert-Test ($order['InstallFiles'] -lt $order['CtlRollback'] -and $order['CtlRollback'] -lt $order['CtlInstall'] -and $order['CtlInstall'] -lt $order['CtlCommit'] -and $order['CtlCommit'] -lt $order['StartServices']) 'rollback/install/commit registration order is unsafe'
        Assert-Test ($order['StopServices'] -lt $order['CtlUninstall'] -and $order['CtlUninstall'] -lt $order['DeleteServices'] -and $order['CtlUninstall'] -lt $order['RemoveFiles']) 'uninstall must refuse before deleting service/payload'
        Assert-Test ($order['InstallInitialize'] -lt $order['RemoveExistingProducts'] -and $order['RemoveExistingProducts'] -lt $order['ProcessComponents']) 'MajorUpgrade must run after InstallInitialize'
        Assert-Test ($order['InstallServices'] -lt $order['MsiConfigureServices'] -and $order['MsiConfigureServices'] -lt $order['StartServices']) 'missing native service configuration sequencing'
        # MajorUpgrade authors Upgrade rows + RemoveExistingProducts, not a MajorUpgrade table.
        $upgrade = @(Read-MsiTable $db Upgrade @('UpgradeCode', 'VersionMin', 'VersionMax', 'Attributes', 'ActionProperty'))
        $older = One-Row ($upgrade | Where-Object ActionProperty -eq 'WIX_UPGRADE_DETECTED') 'missing major upgrade detection'
        $newer = One-Row ($upgrade | Where-Object ActionProperty -eq 'WIX_DOWNGRADE_DETECTED') 'missing downgrade detection'
        Assert-Test ($older.UpgradeCode -eq $properties['UpgradeCode'] -and $older.VersionMax -eq $properties['ProductVersion'] -and (([int]$older.Attributes -band 512) -eq 0)) 'upgrade must exclude same/newer versions'
        Assert-Test ($newer.UpgradeCode -eq $older.UpgradeCode -and $newer.VersionMin -eq $properties['ProductVersion'] -and (([int]$newer.Attributes -band 2) -ne 0)) 'downgrade detection must be detect-only'
        $conditions = @(Read-MsiTable $db LaunchCondition @('Condition', 'Description'))
        [void](One-Row ($conditions | Where-Object Condition -eq 'NOT RollbackDisabled') 'rollback-disabled installs must be refused')
        [void](One-Row ($conditions | Where-Object Condition -eq 'NOT WIX_DOWNGRADE_DETECTED') 'downgrades must be refused')
        Write-Host 'PASS: read-only MSI payload, Service*, CustomAction, sequence and MajorUpgrade table inspection'
        return $properties
    } finally {
        if ($null -ne $db) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Invoke-Msi([string[]]$Arguments, [bool]$ShouldSucceed = $true) {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
    # ERROR_INSTALL_FAILURE=1603 is the expected authored refusal; do not pass
    # missing/corrupt-package failures. /norestart's 3010 is not fixture success.
    # https://learn.microsoft.com/en-us/windows/win32/msi/error-codes
    $expected = 1603
    if ($ShouldSucceed) { $expected = 0 }
    Assert-Test ($process.ExitCode -eq $expected) "unexpected msiexec exit $($process.ExitCode), expected $expected"
}

function Assert-Status([string]$Level, [int]$Expected) {
    & $script:binary ctl status --require $Level | Out-Null
    Assert-Test ($LASTEXITCODE -eq $Expected) "unexpected $Level status: $LASTEXITCODE"
}

function Test-PackageGuard([string]$Binary, [string]$Work) {
    $homeDir = Join-Path $Work 'home'
    $client = Join-Path $homeDir '.aegishook-client'
    $project = Join-Path $Work 'project'
    [void](New-Item -ItemType Directory -Path $client, (Join-Path $project '.claude'))
    $sentinel = Join-Path $client 'sentinel'
    $settings = Join-Path $project '.claude\settings.json'
    Set-Content -LiteralPath $sentinel -Value 'private client sentinel'
    Set-Content -LiteralPath $settings -Value '{"sentinel":"unchanged"}'
    $before = @(Get-ChildItem -LiteralPath $homeDir, $project -File -Recurse | Get-FileHash -Algorithm SHA256 | ForEach-Object { $_.Path + $_.Hash })
    $stderr = Join-Path $Work 'guard.stderr'
    $stdout = Join-Path $Work 'guard.stdout'
    $oldHome, $oldUserProfile = $env:HOME, $env:USERPROFILE
    try {
        $env:HOME = $homeDir
        $env:USERPROFILE = $homeDir
        # Synthetic code + valid arguments: do not accept an unrelated network failure.
        $stdin = Join-Path $Work 'guard.stdin'
        Set-Content -LiteralPath $stdin -Encoding Ascii -Value ('0' * 64)
        $process = Start-Process -FilePath $Binary -ArgumentList @('client', 'install', '--agent', 'claude', '--scope', 'project', '--project', ('"' + $project + '"'), '--client-dir', ('"' + $client + '"'), '--endpoint', 'http://127.0.0.1:1', '--code-stdin') -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
        Assert-Test ($process.ExitCode -eq 1) 'package client guard returned wrong exit code'
        Assert-Test ((Get-Item -LiteralPath $stdout).Length -eq 0) 'package client guard wrote stdout'
        Assert-Test ((Get-Content -LiteralPath $stderr -Raw).Trim() -eq 'client install cannot use the package binary; use hook.sh or hook.ps1 to create a verified private copy') 'package-specific client refusal was not reached'
    } finally { $env:HOME = $oldHome; $env:USERPROFILE = $oldUserProfile }
    $after = @(Get-ChildItem -LiteralPath $homeDir, $project -File -Recurse | Get-FileHash -Algorithm SHA256 | ForEach-Object { $_.Path + $_.Hash })
    Assert-Test (-not (Compare-Object $before $after)) 'package client guard changed isolated hook files'
}

function Assert-ProductInstalled([string]$ProductCode, [bool]$Expected) {
    # INSTALLSTATE_DEFAULT=5. Unknown/absent are not installed products.
    # https://learn.microsoft.com/en-us/windows/win32/msi/installer-productstate
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try { Assert-Test (($installer.ProductState($ProductCode) -eq 5) -eq $Expected) 'unexpected MSI product registration' }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
}

function Test-Lifecycle([string]$Path, [string]$Upgrade, [hashtable]$Package) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-Test ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'lifecycle requires an elevated runner'
    Assert-Test ($env:TG_SENTRY_NATIVE_DISPOSABLE -eq '1') 'lifecycle requires TG_SENTRY_NATIVE_DISPOSABLE=1 on a disposable runner'
    $root = Join-Path $env:ProgramData 'TG-Sentry'
    $app = Join-Path $env:ProgramFiles 'TG-Sentry'
    $script:binary = Join-Path $app 'aegishook.exe'
    Assert-Test (-not (Test-Path -LiteralPath $root) -and -not (Test-Path -LiteralPath $app)) 'lifecycle requires clean machine and payload roots'
    Assert-Test ($null -eq (Get-Service TGSentryEndpoint -ErrorAction SilentlyContinue)) 'service already exists'
    Assert-ProductInstalled $Package['ProductCode'] $false
    $upgradePackage = $null
    if ($Upgrade) {
        $upgradePackage = Inspect-Msi $Upgrade
        Assert-Test ([version]$upgradePackage['ProductVersion'] -gt [version]$Package['ProductVersion']) 'upgrade fixture must have a distinct higher version'
        Assert-ProductInstalled $upgradePackage['ProductCode'] $false
    }
    $managed = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json'
    Assert-Test (-not (Test-Path -LiteralPath $managed)) 'managed fixture destination already exists'
    $logs = Join-Path ([IO.Path]::GetTempPath()) ('tg-sentry-msi-test-' + [guid]::NewGuid())
    [void](New-Item -ItemType Directory -Path $logs)
    # Keep logs on failure for diagnosis; never read private credential files.
    Invoke-Msi @('/i', ('"' + $Path + '"'), '/qn', '/norestart', 'RollbackDisabled=1', '/L*v', ('"' + "$logs\rollback-disabled.log" + '"')) $false
    Assert-Test (-not (Test-Path -LiteralPath $root) -and -not (Test-Path -LiteralPath $app)) 'rollback-disabled install changed disk'
    Invoke-Msi @('/i', ('"' + $Path + '"'), '/qn', '/norestart', '/L*v', ('"' + "$logs\install.log" + '"'))
    Assert-Status installed 0
    Assert-Status service 0
    Assert-Status enrolled 30
    $manifest = Join-Path $root 'private\client.json'
    $before = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash
    $node = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).nodeId
    Invoke-Msi @('/i', ('"' + $Path + '"'), '/qn', '/norestart')
    Assert-Test ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -eq $before) 'duplicate install changed manifest'
    $current = $Path
    if ($Upgrade) {
        Invoke-Msi @('/i', ('"' + $Upgrade + '"'), '/qn', '/norestart')
        Assert-ProductInstalled $upgradePackage['ProductCode'] $true
        Assert-ProductInstalled $Package['ProductCode'] $false
        Assert-Status service 0
        Assert-Test ((Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).nodeId -eq $node) 'upgrade changed machine identity'
        Invoke-Msi @('/i', ('"' + $Path + '"'), '/qn', '/norestart') $false
        Assert-Status service 0
        $current = $Upgrade
    } else { Write-Output 'NOT RUN: distinct-version upgrade/downgrade (supply -UpgradeMsi)' }
    Test-PackageGuard $script:binary $logs
    # T8: refusal must preserve payload, managed file, and restore SCM via MSI rollback.
    [void](New-Item -ItemType Directory -Path (Split-Path $managed) -Force)
    try {
        Set-Content -LiteralPath $managed -Value ('{"reference":"' + $script:binary.Replace('\', '\\') + '"}')
        $managedHash = (Get-FileHash -LiteralPath $managed -Algorithm SHA256).Hash
        Invoke-Msi @('/x', ('"' + $current + '"'), '/qn', '/norestart') $false
        Assert-Test ((Test-Path -LiteralPath $script:binary) -and (Get-FileHash -LiteralPath $managed -Algorithm SHA256).Hash -eq $managedHash) 'managed-reference refusal did not preserve payload/fixture'
        Assert-Status service 0
    } finally { Remove-Item -LiteralPath $managed }
    $foreign = Join-Path $root 'private\foreign-test'
    Set-Content -LiteralPath $foreign -Value 'foreign native-test sentinel'
    Invoke-Msi @('/x', ('"' + $current + '"'), '/qn', '/norestart') $false
    Assert-Test ((Test-Path -LiteralPath $foreign) -and (Test-Path -LiteralPath $script:binary)) 'foreign state or payload removed'
    Remove-Item -LiteralPath $foreign
    # Pending #82: S1 may already have removed owned state before refusing a
    # foreign file. Explicitly reconstruct it for cleanup; this is NOT proof of
    # transaction-safe refused uninstall. #82 owns the core preflight fix.
    & $script:binary ctl system-install --no-commit | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'cannot restore machine state after foreign refusal'
    & $script:binary ctl commit | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'cannot commit restored fixture state'
    Invoke-Msi @('/x', ('"' + $current + '"'), '/qn', '/norestart', '/L*v', ('"' + "$logs\uninstall.log" + '"'))
    Assert-Test (-not (Test-Path -LiteralPath $script:binary) -and $null -eq (Get-Service TGSentryEndpoint -ErrorAction SilentlyContinue)) 'payload/service survived uninstall'
    Assert-Test (-not (Select-String -Path "$logs\*.log" -Pattern '[0-9a-fA-F]{64}' -Quiet)) 'T6: possible token in MSI logs'
    Write-Output "PASS: native unprovisioned lifecycle/refusal/uninstall; logs: $logs"
    Write-Output 'NOT RUN: provisioned identity/cache upgrade, enrollment failure/retry, failed upgrade rollback, commit injection, reboot and timed recovery; release-runner fixtures required'
    Write-Output 'PENDING #82: full machine-state preservation after a refused foreign-file uninstall'
}

Assert-Test ($env:OS -eq 'Windows_NT') 'Windows Installer inspection requires Windows'
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$package = Inspect-Msi $Msi
if (-not $Inspect) {
    if ($UpgradeMsi) { $UpgradeMsi = (Resolve-Path -LiteralPath $UpgradeMsi).Path }
    Test-Lifecycle $Msi $UpgradeMsi $package
}

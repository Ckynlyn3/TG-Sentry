#Requires -PSEdition Desktop
# Windows PowerShell 5.1 only: ci.yml pins `shell: powershell`; PS7 redirect/header semantics differ.
# Runs only in an isolated Windows CI worker, never against a user's console.
param([Parameter(Mandatory=$true)][string]$Binary)
$ErrorActionPreference='Stop'
if ($env:CI -ne 'true' -or $env:OS -ne 'Windows_NT') {throw 'This smoke test requires an isolated Windows CI worker.'}
$Binary=(Resolve-Path $Binary).Path
$root=Join-Path ([IO.Path]::GetTempPath()) ('aegishook-ci-'+[Guid]::NewGuid().ToString('N'))
$data=Join-Path $root 'server'
$client=Join-Path $root 'client'
$project=Join-Path $root 'project'
$previousClaude=$env:CLAUDE_CONFIG_DIR
$env:CLAUDE_CONFIG_DIR=Join-Path $root 'claude'
$service=$null
$provider=$null
$oidc=@{
    TG_SENTRY_OIDC_ISSUER=''
    TG_SENTRY_OIDC_CLIENT_ID='client'
    TG_SENTRY_OIDC_CLIENT_SECRET='synthetic-fixture-secret'
    TG_SENTRY_OIDC_REDIRECT_URL='http://127.0.0.1:18790/api/v1/auth/callback'
    TG_SENTRY_OIDC_ROLE_CLAIM='roles'
    TG_SENTRY_OIDC_ROLE_MAP='admin=admins,auditor=auditors,readonly=readers'
    TG_SENTRY_OIDC_TRUSTED_AUDIENCES=''
}
$previousOIDC=@{}
foreach ($key in $oidc.Keys) {$previousOIDC[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}

function Invoke-TestOIDCRedirect([uri]$Uri, [Microsoft.PowerShell.Commands.WebRequestSession]$Session, [uri]$CookieUri=$Uri) {
    # Microsoft: -MaximumRedirection 0 prevents redirects; -WebSession shares cookies between requests.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1#-maximumredirection
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1#-websession
    # Windows PowerShell emits the 302 response before its nonterminating MaximumRedirectExceeded error.
    $response=Invoke-WebRequest -UseBasicParsing -Uri $Uri -WebSession $Session -MaximumRedirection 0 -ErrorAction SilentlyContinue -ErrorVariable redirectErrors
    foreach ($failure in $redirectErrors) {
        if ($failure.FullyQualifiedErrorId -notlike 'MaximumRedirectExceeded,*') {throw $failure}
    }
    if (-not $response -or [int]$response.StatusCode -ne 302 -or -not $response.Headers['Location']) {throw 'Expected an OIDC 302 with Location.'}
    foreach ($cookie in $response.BaseResponse.Headers.GetValues('Set-Cookie')) {
        $Session.Cookies.SetCookies($CookieUri,$cookie)
    }
    return [uri]::new($Uri,$response.Headers['Location'])
}

try {
    New-Item -ItemType Directory -Path $root,$project,$env:CLAUDE_CONFIG_DIR | Out-Null
    if (Get-NetTCPConnection -LocalPort 18790 -State Listen -ErrorAction SilentlyContinue) {throw 'Test port already occupied.'}
    $fixture=(Resolve-Path (Join-Path (Split-Path $Binary) 'test-oidc.exe')).Path
    $providerOut=Join-Path $root 'oidc-stdout'
    $provider=Start-Process -FilePath $fixture -ArgumentList @('--port','0','--subject','subject') -PassThru -RedirectStandardOutput $providerOut -RedirectStandardError (Join-Path $root 'oidc-stderr')
    # Reuse the service readiness budget; the fixture reports its OS-selected loopback port.
    for ($i=0;$i -lt 60;$i++) {
        if ($provider.HasExited) {throw 'Test OIDC provider exited.'}
        if (Test-Path $providerOut) {
            $line=Get-Content $providerOut | Where-Object {$_ -match '^test OIDC ready http://127\.0\.0\.1:\d+$'} | Select-Object -First 1
            if ($line) {$oidc.TG_SENTRY_OIDC_ISSUER=$line.Substring('test OIDC ready '.Length); break}
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $oidc.TG_SENTRY_OIDC_ISSUER) {throw 'Test OIDC provider did not start.'}
    & $Binary admin bind --issuer $oidc.TG_SENTRY_OIDC_ISSUER --subject subject --data-dir $data
    if ($LASTEXITCODE -ne 0) {throw 'Test admin binding failed.'}
    foreach ($key in $oidc.Keys) {[Environment]::SetEnvironmentVariable($key,$oidc[$key],'Process')}
    $service=Start-Process -FilePath $Binary -ArgumentList @('serve','--addr','127.0.0.1:18790','--data-dir',('"'+$data+'"'),'--agent-dir',('"'+(Join-Path $root 'pi')+'"')) -PassThru -RedirectStandardOutput (Join-Path $root 'stdout') -RedirectStandardError (Join-Path $root 'stderr')
    $ready=$false
    for ($i=0;$i -lt 60;$i++) {
        Start-Sleep -Milliseconds 250
        try { $null=Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:18790/'; $ready=$true; break } catch {}
    }
    if (-not $ready) {throw 'Test console did not start.'}
    # Mirror scripts/test-oidc.mjs: retain each 302's cookies before the next hop.
    $session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $base=[uri]'http://127.0.0.1:18790/'
    # .NET Framework rejects a cookie whose Path is not a prefix of its response URI.
    # Anchor the callback-scoped transaction cookie at the callback, not /auth/login.
    # https://github.com/microsoft/referencesource/blob/main/System/net/System/Net/cookie.cs (VerifySetDefaults)
    $authorize=Invoke-TestOIDCRedirect ([uri]::new($base,'api/v1/auth/login')) $session ([uri]$oidc.TG_SENTRY_OIDC_REDIRECT_URL)
    if ($authorize.GetLeftPart([UriPartial]::Authority) -ne $oidc.TG_SENTRY_OIDC_ISSUER -or $authorize.AbsolutePath -ne '/authorize') {throw 'Unexpected OIDC authorization redirect.'}
    # Do not send control-plane cookies to the provider (cookies are not port-scoped).
    $callback=Invoke-TestOIDCRedirect $authorize (New-Object Microsoft.PowerShell.Commands.WebRequestSession)
    if ($callback.GetLeftPart([UriPartial]::Authority) -ne $base.GetLeftPart([UriPartial]::Authority) -or $callback.AbsolutePath -ne '/api/v1/auth/callback') {throw 'Unexpected OIDC callback redirect.'}
    if (-not $session.Cookies.GetCookies($callback)['aegis_oidc_tx']) {throw 'Missing OIDC transaction cookie.'}
    $console=Invoke-TestOIDCRedirect $callback $session
    if ($console.AbsoluteUri -ne $base.AbsoluteUri) {throw 'Unexpected OIDC console redirect.'}
    if (-not $session.Cookies.GetCookies($base)['aegis_session']) {throw 'Missing OIDC session cookie.'}
    $identity=Invoke-RestMethod -Uri ([uri]::new($base,'api/v1/me')) -WebSession $session
    if ($identity.kind -ne 'human' -or $identity.role -ne 'admin' -or $identity.subject -ne 'subject') {throw 'SSO did not create a human admin session.'}
    $code=Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:18790/api/v1/client-enrollments' -ContentType 'application/json' -Body '{"name":"Windows CI"}' -WebSession $session
    $codePath=Join-Path $root 'enrollment'
    [IO.File]::WriteAllText($codePath,$code.code)
    $script=Join-Path $PSScriptRoot 'hook.ps1'
    $settings=Join-Path $env:CLAUDE_CONFIG_DIR 'settings.json'
    [IO.File]::WriteAllText($settings,'{"foreign":"preserve"}')
    & $script -Action install -Agent claude -Scope global -Endpoint 'http://127.0.0.1:18790' -CodeFile $codePath -Binary $Binary -ClientDir $client
    & $script -Action install -Agent claude -Scope global -Endpoint 'http://127.0.0.1:18790' -ClientDir $client
    & $script -Action install -Agent claude -Scope project -Project $project -SwitchScope -Endpoint 'http://127.0.0.1:18790' -ClientDir $client
    $doc=Get-Content -Raw $settings | ConvertFrom-Json
    if ($doc.foreign -ne 'preserve' -or ($doc.PSObject.Properties.Name -contains 'hooks')) {throw 'Global scope switch changed foreign config or retained Hooks.'}
    & $script -Action uninstall -Agent claude -Scope project -Project $project -ClientDir $client
    & $script -Action uninstall -Agent claude -Scope project -Project $project -ClientDir $client
    foreach ($path in @((Join-Path $project '.claude/settings.json'),(Join-Path $client 'client.json'),(Join-Path $client 'adapter/connection.json'),(Join-Path $client 'aegishook.exe'))) {if (Test-Path $path) {throw 'Uninstall left an owned resource.'}}
    Write-Output 'PASS: Windows installer, repeated install, scope switch, foreign configuration preservation and repeated uninstall.'
} finally {
    if ($service -and -not $service.HasExited) {$service.Kill();$service.WaitForExit()}
    if ($provider -and -not $provider.HasExited) {$provider.Kill();$provider.WaitForExit()}
    foreach ($key in $previousOIDC.Keys) {[Environment]::SetEnvironmentVariable($key,$previousOIDC[$key],'Process')}
    $env:CLAUDE_CONFIG_DIR=$previousClaude
    if (Test-Path $root) {Remove-Item -LiteralPath $root -Recurse -Force}
}

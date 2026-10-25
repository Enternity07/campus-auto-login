#requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'SzuPublicAutoLogin.ps1')
$script:TestsPassed = 0
function Assert-True([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:TestsPassed++
    Write-Output ('PASS: ' + $Name)
}
function Assert-Throws([scriptblock]$Block, [string]$Name) {
    $failed = $false
    try { & $Block | Out-Null } catch { $failed = $true }
    Assert-True $failed $Name
}

Assert-PortalUrl 'https://net.szu.edu.cn/cgi-bin/srun_portal'
Assert-Throws { Assert-PortalUrl 'http://net.szu.edu.cn/cgi-bin/srun_portal' } 'Reject HTTPS downgrade'
Assert-Throws { Assert-PortalUrl 'https://evil.example/cgi-bin/srun_portal' } 'Reject a different credential recipient'
Assert-Throws { Assert-PortalUrl 'https://net.szu.edu.cn@evil.example/' } 'Reject userinfo host tricks'
Assert-Throws { Assert-PortalUrl 'https://net.szu.edu.cn:8800/' } 'Do not send authentication to self-service port'
Assert-True ((Resolve-SzuPageRedirect 'https://net.szu.edu.cn/' '/srun_portal_pc?ac_id=1&amp;theme=proyx').Contains('&theme=')) 'Resolve official meta redirect and HTML entities'
Assert-Throws { Resolve-SzuPageRedirect 'https://net.szu.edu.cn/' 'https://evil.example/' } 'Reject cross-host page redirects'
Assert-Throws { Resolve-SzuPageRedirect 'https://net.szu.edu.cn/' '/cgi-bin/srun_portal' } 'Never follow a page redirect into a login API'
Assert-True ((Get-WorkerArguments).Contains('SzuPublicAutoLogin.ps1')) 'Background and autostart use the public-area entry script'
Assert-True ($script:CredentialPath.EndsWith('.data\public\credential.xml')) 'Public-area credentials are separate from dorm credentials'
$publicId = Get-InstanceId
$script:InstanceSuffix = ''
$dormId = Get-InstanceId
$script:InstanceSuffix = '-Public'
Assert-True ($publicId -eq ($dormId + '-Public')) 'Independent worker and startup identity preserves original dorm identity'

$html = 'var CONFIG = {acid:"17",ip:"172.31.100.234"}; <script src="Portal.js"></script>'
$parsed = ConvertFrom-SzuPage $html
Assert-True ($parsed.AcId -eq '17' -and $parsed.Ip -eq '172.31.100.234') 'Discover controller and current IP from live page configuration'
Assert-Throws { ConvertFrom-SzuPage 'var CONFIG={acid:"1",ip:"0.0.0.0"}; Portal.js' } 'Reject unspecified page IP'
Assert-Throws { ConvertFrom-SzuPage 'var CONFIG={acid:"1",ip:"172.31.1.2",portal:{"AccountFilter":"tolower"}}; Portal.js' } 'Pause when page adds unsupported account transformation'

$fixtures = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'srun-vectors.json') -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($vector in $fixtures.vectors) {
    $credential = New-Object Management.Automation.PSCredential($vector.account, (ConvertTo-SecureString $vector.password -AsPlainText -Force))
    $context = [pscustomobject]@{ Ip = $vector.ip; AcId = $vector.acid }
    $parameters = New-SrunParameters $context $credential $vector.token
    Assert-True ($parameters.info -eq $vector.info) 'bx1 info matches actual SZU browser encoding fixture'
    Assert-True ($parameters.password -eq ('{MD5}' + $vector.digest)) 'HMAC-MD5 password matches independent reference'
    Assert-True ($parameters.chksum -eq $vector.checksum) 'SHA1 request checksum matches browser protocol reference'
    Assert-True (-not $parameters.password.Contains($vector.password) -and -not $parameters.info.Contains($vector.password)) 'Login query never contains plaintext password'
}
$vector = $fixtures.vectors[0]
$credential = New-Object Management.Automation.PSCredential($vector.account, (ConvertTo-SecureString $vector.password -AsPlainText -Force))
$context = [pscustomobject]@{ Ip = '172.31.100.50'; AcId = '1' }
Assert-Throws { New-SrunParameters $context $credential 'invalid-challenge' } 'Reject malformed challenge before authenticating'

$script:FakeStatus = 'ok'
function Invoke-PortalJson {
    param($Base,$Parameters)
    return [pscustomobject]@{ error = $script:FakeStatus; res = $script:FakeStatus }
}
Assert-True ((Get-PortalStatus).result -eq 1) 'Map SRun online response to online state'
$script:FakeStatus = 'not_online_error'
Assert-True ((Get-PortalStatus).result -eq 0) 'Map SRun offline response to offline state'
$script:FakeStatus = 'unexpected_error'
Assert-Throws { Get-PortalStatus } 'Unknown status does not trigger authentication'

$script:CaptchaData = '0'
$script:ChallengeCalls = 0
$script:AuthenticationCalls = 0
$script:AuthError = 'ok'
$script:AuthCode = ''
$script:FreshIp = $vector.ip
function Invoke-SzuRequest {
    param($Url,[switch]$PageRedirects,[switch]$AllowNotFound)
    return [pscustomobject]@{ Status = 200; Text = ('{"code":0,"data":"' + $script:CaptchaData + '"}'); Uri = $Url }
}
function Invoke-PortalJson {
    param($Base,$Parameters)
    if ($Base.EndsWith('/get_challenge')) {
        $script:ChallengeCalls++
        return [pscustomobject]@{ error = 'ok'; client_ip = $script:FreshIp; challenge = $vector.token }
    }
    if ($Base.EndsWith('/srun_portal')) {
        $script:AuthenticationCalls++
        $script:SubmittedParameters = $Parameters
        return [pscustomobject]@{ error = $script:AuthError; ecode = $script:AuthCode; error_msg = '' }
    }
    throw 'Unexpected request in mock'
}
$login = Invoke-PortalLogin $context $credential
Assert-True ($login.result -eq 1 -and $script:AuthenticationCalls -eq 1) 'Captcha-free challenge flow submits exactly one login'
Assert-True ($script:SubmittedParameters.ip -eq $vector.ip -and $script:SubmittedParameters.info -eq $vector.info) 'Use fresh challenge IP when page IP has changed'

$script:CaptchaData = '1'
$before = $script:AuthenticationCalls
$challengeBefore = $script:ChallengeCalls
Assert-Throws { Invoke-PortalLogin $context $credential } 'Visible captcha stops before challenge and login'
Assert-True ($script:AuthenticationCalls -eq $before -and $script:ChallengeCalls -eq $challengeBefore) 'Captcha requirement sends no authentication'
$script:CaptchaData = 'unexpected'
Assert-Throws { Invoke-PortalLogin $context $credential } 'Unknown captcha state stops login'
Assert-True ($script:AuthenticationCalls -eq $before) 'Unknown captcha state sends no authentication'

$script:CaptchaData = '0'
$script:FreshIp = '0.0.0.0'
Assert-Throws { Invoke-PortalLogin $context $credential } 'Reject invalid challenge IP'
Assert-True ($script:AuthenticationCalls -eq $before) 'Invalid challenge IP sends no authentication'
$script:FreshIp = $vector.ip
$script:AuthError = 'login_error'
$script:AuthCode = 'E2553'
$login = Invoke-PortalLogin $context $credential
Assert-True ((Get-SafeLoginMessage $login $credential) -match '密码') 'Map SZU password error into immediate pause classification'
$script:AuthCode = 'E2620'
$login = Invoke-PortalLogin $context $credential
Assert-True ((Get-SafeLoginMessage $login $credential) -match '上限') 'Map online device limit into pause classification'
$script:AuthError = 'vcode_error'
Assert-Throws { Invoke-PortalLogin $context $credential } 'Server-side verification requirement pauses login'

Write-Output ('All ' + $script:TestsPassed + ' public-area checks passed. No real campus credential was loaded or submitted.')

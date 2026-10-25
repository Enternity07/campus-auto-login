#requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'CampusAutoLogin.ps1')
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

$plain = ConvertFrom-PortalJson '{"result":1}'
Assert-True ($plain.result -eq 1) 'Parse plain JSON'
$jsonp = ConvertFrom-PortalJson "`r`ncampusCallback({`"result`":0});`r`n"
Assert-True ($jsonp.result -eq 0) 'Parse JSONP without evaluating JavaScript'
Assert-Throws { ConvertFrom-PortalJson 'campusCallback({"result":0});alert(1)' } 'Reject executable suffix'
Assert-Throws { ConvertFrom-PortalJson '<html>login required</html>' } 'Reject redirected HTML'

Assert-PortalUrl 'http://172.30.255.42:801/eportal/portal/login'
Assert-Throws { Assert-PortalUrl 'http://evil.example/eportal/portal/login' } 'Reject other credential recipient'
Assert-Throws { Assert-PortalUrl 'http://172.30.255.42@evil.example/' } 'Reject userinfo host trick'
Assert-Throws { Assert-PortalUrl 'http://172.30.255.42:8080/' } 'Reject unexpected port'

$secret = 'test&+?=中文# password'
$credential = New-Object Management.Automation.PSCredential('testStudent', (ConvertTo-SecureString $secret -AsPlainText -Force))
$context = [pscustomobject]@{
    Ip = '172.29.97.123'; Mac = '001122334455'; Method = '1'
    Config = [pscustomobject]@{ account_prefix = '1'; account_suffix = ''; custom_perceive = '0' }
}
$parameters = New-LoginParameters $context $credential
Assert-True ($parameters.user_account -eq ',0,testStudent') 'Match actual PC account prefix'
Assert-True ($parameters.wlan_user_ip -eq '172.29.97.123') 'Use newly discovered IP'
$encoded = New-QueryUrl 'http://172.30.255.42:801/eportal/portal/login' $parameters
Assert-True ($encoded.Contains('user_password=test%26%2B%3F%3D%E4%B8%AD%E6%96%87%23%20password')) 'Encode password special characters exactly once'
Assert-True (-not $script:PageUrl.Contains('wlanuserip=')) 'Never carry stale IP from shared link'

$reply = [pscustomobject]@{ result = 0; msg = 'testStudent test&+?=中文# password http://host/?user_password=secret'; ret_code = '1' }
$safe = Get-SafeLoginMessage $reply $credential
Assert-True (-not $safe.Contains('testStudent') -and -not $safe.Contains('secret') -and -not $safe.Contains($secret)) 'Never log echoed credentials or raw URLs'

$rejected = [pscustomobject]@{ Kind = 'Rejected' }
$first = Get-CycleDecision $rejected 0
$second = Get-CycleDecision $rejected 1
$third = Get-CycleDecision $rejected 2
Assert-True (-not $first.Pause -and $first.Delay -eq 120 -and $first.Rejections -eq 1) 'Back off 2 minutes after first rejection'
Assert-True (-not $second.Pause -and $second.Delay -eq 240) 'Back off 4 minutes after second rejection'
Assert-True ($third.Pause) 'Pause after third rejection'
Assert-True ((Get-CycleDecision ([pscustomobject]@{ Kind = 'Manual' }) 0).Pause) 'Pause immediately for password or verification errors'
Assert-True ((Get-CycleDecision ([pscustomobject]@{ Kind = 'Online' }) 2).Rejections -eq 0) 'Reset rejection counter once online'

# Mock the network boundary. These credentials never leave this process.
$script:LoginCalls = 0
$script:StatusCalls = 0
function Get-PortalStatus { $script:StatusCalls++; return [pscustomobject]@{ result = 1 } }
function Get-LoginContext { throw 'Must not load a login page while online' }
function Invoke-PortalLogin { $script:LoginCalls++; throw 'Must not submit credentials while online' }
$cycle = Invoke-ConnectionCycle $credential
Assert-True ($cycle.Kind -eq 'Online' -and $script:LoginCalls -eq 0) 'Online cycle never submits credentials'

$script:StatusCalls = 0
function Get-PortalStatus {
    $script:StatusCalls++
    if ($script:StatusCalls -eq 1) { return [pscustomobject]@{ result = 0 } }
    return [pscustomobject]@{ result = 1 }
}
function Get-LoginContext { return $context }
function Invoke-PortalLogin { $script:LoginCalls++; return [pscustomobject]@{ result = 1 } }
$cycle = Invoke-ConnectionCycle $credential
Assert-True ($cycle.Kind -eq 'Restored' -and $script:LoginCalls -eq 1 -and $script:StatusCalls -eq 2) 'Offline cycle logs in once and confirms server status'

function Get-PortalStatus { return [pscustomobject]@{ result = 0 } }
$cycle = Invoke-ConnectionCycle $credential
Assert-True ($cycle.Kind -eq 'Rejected') 'Never report restored while confirmation stays offline'

$before = $script:LoginCalls
function Get-PortalStatus { throw 'Network unavailable' }
Assert-Throws { Invoke-ConnectionCycle $credential } 'Propagate unknown status without attempting authentication'
Assert-True ($script:LoginCalls -eq $before) 'Network failure sends zero credentials'

function Get-PortalStatus { return [pscustomobject]@{ result = 0 } }
function Get-LoginContext { throw 'MANUAL:验证码' }
$before = $script:LoginCalls
Assert-Throws { Invoke-ConnectionCycle $credential } 'Visible captcha stops the login flow'
Assert-True ($script:LoginCalls -eq $before) 'Captcha sends zero credentials'

$testData = Join-Path $PSScriptRoot '.test-data'
$null = New-Item -Path $testData -ItemType Directory -Force
$credentialFile = Join-Path $testData 'fake-credential.xml'
try {
    $credential | Export-Clixml -LiteralPath $credentialFile -Encoding UTF8
    $restored = Import-Clixml -LiteralPath $credentialFile
    Assert-True ($restored.GetNetworkCredential().Password -eq $secret) 'Windows DPAPI credential roundtrip'
    $xml = Get-Content -LiteralPath $credentialFile -Raw
    Assert-True (-not $xml.Contains($secret) -and $xml.Contains('<SS ')) 'Password is encrypted on disk'
} finally {
    if (Test-Path -LiteralPath $credentialFile) { Remove-Item -LiteralPath $credentialFile }
    if (@(Get-ChildItem -LiteralPath $testData).Count -eq 0) { Remove-Item -LiteralPath $testData }
}
Write-Output ('All ' + $script:TestsPassed + ' checks passed. No real login was attempted.')

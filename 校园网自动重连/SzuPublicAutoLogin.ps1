#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu','Setup','Worker','Once','Stop','Diagnose','EnableStartup','DisableStartup')]
    [string]$Action = 'Menu'
)

$publicEntryPath = $PSCommandPath
$publicScriptRoot = $PSScriptRoot
. (Join-Path $publicScriptRoot 'CampusAutoLogin.ps1') -Action $Action
$script:DisplayName = '深圳大学公共区校园网助手'
$script:EntryScriptPath = $publicEntryPath
$script:InstanceSuffix = '-Public'
$script:NetworkDescription = '适用：深大公共 / 教学办公区 SZU_WLAN，https://net.szu.edu.cn/。'
$script:AccountInstructions = '请输入 net.szu.edu.cn 认证页面使用的本人账号密码；密码不会显示。'
$script:AccountPrompt = '深大公共区上网账号（以认证页为准，空行取消）'
$script:PasswordPrompt = '深大公共区上网密码（以认证页为准）'
$script:PortalHost = 'net.szu.edu.cn'
$script:BaseUrl = 'https://net.szu.edu.cn'
$script:PageUrl = $script:BaseUrl + '/'
$script:DataDir = Join-Path $publicScriptRoot '.data\public'
$script:CredentialPath = Join-Path $script:DataDir 'credential.xml'
$script:PausePath = Join-Path $script:DataDir 'paused.txt'
$script:LogPath = Join-Path $script:DataDir 'reconnect.log'
$script:StatusPath = Join-Path $script:DataDir 'status.json'

if (-not ('SzuSrunCodec' -as [type])) {
    Add-Type -Path (Join-Path $publicScriptRoot 'SrunCodec.cs')
}

function Assert-PortalUrl([string]$Url) {
    $target = [Uri]$Url
    if ($target.Scheme -ne 'https' -or $target.Host -ne 'net.szu.edu.cn' -or
        $target.Port -ne 443 -or $target.UserInfo -ne '') {
        throw '已阻止向非深圳大学 HTTPS 认证服务器发送请求。'
    }
}

function Resolve-SzuPageRedirect([string]$Current, [string]$Location) {
    $next = [Uri]::new([Uri]$Current, [Net.WebUtility]::HtmlDecode($Location))
    Assert-PortalUrl $next.AbsoluteUri
    if ($next.AbsolutePath.StartsWith('/cgi-bin/') -or $next.AbsolutePath.StartsWith('/v2/')) {
        throw '认证页面跳转异常，本次不登录。'
    }
    return $next.AbsoluteUri
}

function Invoke-SzuRequest([string]$Url, [switch]$PageRedirects, [switch]$AllowNotFound) {
    $current = $Url
    for ($hop = 0; $hop -lt 6; $hop++) {
        Assert-PortalUrl $current
        if ($null -ne $script:StopSignal -and $script:StopSignal.WaitOne(0)) { throw 'STOP:后台检测正在停止。' }
        $response = $null
        $reader = $null
        try {
            $request = [Net.HttpWebRequest]::Create($current)
            $request.Proxy = $null
            $request.AllowAutoRedirect = $false
            $request.Timeout = $script:TimeoutMilliseconds
            $request.ReadWriteTimeout = $script:TimeoutMilliseconds
            $request.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
            $request.UserAgent = 'SZU-CampusAutoLogin/2.0 Windows'
            $request.CachePolicy = New-Object Net.Cache.RequestCachePolicy([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
            try { $response = $request.GetResponse() }
            catch [Net.WebException] {
                if ($AllowNotFound -and $null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
                    $_.Exception.Response.Dispose()
                    return [pscustomobject]@{ Status = 404; Text = ''; Uri = $current }
                }
                if ($null -ne $_.Exception.Response) { $_.Exception.Response.Dispose() }
                throw '认证服务器暂不可达，请确认已连接深大公共区网络。'
            }
            $status = [int]$response.StatusCode
            if ($status -in @(301,302,303,307,308)) {
                if (-not $PageRedirects) { throw '认证接口要求跳转，本次不提交后续请求。' }
                $current = Resolve-SzuPageRedirect $current $response.Headers['Location']
                continue
            }
            if ($status -ne 200) { throw '认证服务器响应异常。' }
            $encoding = [Text.Encoding]::UTF8
            if ($response.ContentType -match 'charset\s*=\s*["'']?([\w-]+)') {
                $encoding = [Text.Encoding]::GetEncoding($Matches[1])
            }
            $reader = New-Object IO.StreamReader($response.GetResponseStream(), $encoding, $true)
            $buffer = New-Object char[] 8192
            $text = New-Object Text.StringBuilder
            while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $null = $text.Append($buffer, 0, $count)
                if ($text.Length -gt 2097152) { throw '认证服务器响应过大。' }
            }
            $body = $text.ToString()
            if ($PageRedirects) {
                $meta = [regex]::Match($body, '<meta\b[^>]*http-equiv\s*=\s*["'']refresh["''][^>]*content\s*=\s*["''][^"'']*url\s*=\s*([^"'']+)', 'IgnoreCase')
                if ($meta.Success) {
                    $current = Resolve-SzuPageRedirect $current $meta.Groups[1].Value.Trim()
                    continue
                }
            }
            return [pscustomobject]@{ Status = 200; Text = $body; Uri = $current }
        } catch {
            # 不能输出原始网络异常，它可能包含用户名、散列或 info 参数。
            if ($_.Exception.Message.StartsWith('STOP:')) { throw 'STOP:后台检测正在停止。' }
            throw '深大公共区 HTTPS 请求未完成；请检查网络、证书或认证页面。'
        } finally {
            if ($null -ne $reader) { $reader.Dispose() }
            if ($null -ne $response) { $response.Dispose() }
        }
    }
    throw '认证页面跳转次数过多，本次不登录。'
}

function Invoke-PortalRequest([string]$Url) { return (Invoke-SzuRequest $Url).Text }

function Invoke-PortalJson([string]$Base, [System.Collections.IDictionary]$Parameters) {
    $query = [ordered]@{ callback = 'szuCallback'; '_' = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
    foreach ($entry in $Parameters.GetEnumerator()) { $query[$entry.Key] = $entry.Value }
    return ConvertFrom-PortalJson (Invoke-PortalRequest (New-QueryUrl $Base $query))
}

function Get-PortalStatus {
    $status = Invoke-PortalJson ($script:BaseUrl + '/cgi-bin/rad_user_info') @{}
    $errorName = [string](Get-Field $status 'error' '')
    $resultName = [string](Get-Field $status 'res' '')
    if ($errorName -eq 'ok' -and $resultName -in @('','ok')) {
        return [pscustomobject]@{ result = 1 }
    }
    if ($errorName -eq 'not_online_error' -or $resultName -eq 'not_online_error') {
        return [pscustomobject]@{ result = 0 }
    }
    throw '公共区认证状态未知，本次不提交账号密码。'
}

function ConvertFrom-SzuPage([string]$Html) {
    if ($Html -notmatch '\bCONFIG\s*=' -or $Html -notmatch 'srun|Portal\.js') {
        throw 'MANUAL:公共区认证页面已变化，请在浏览器确认。'
    }
    $acid = [regex]::Match($Html, '\bacid\s*:\s*["''](\d{1,6})["'']').Groups[1].Value
    $ipText = [regex]::Match($Html, '\bip\s*:\s*["'']([^"'']+)["'']').Groups[1].Value
    $address = $null
    if (-not $acid -or -not [Net.IPAddress]::TryParse($ipText, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ipText -eq '0.0.0.0') {
        throw '公共区页面未提供有效接入控制器或 IPv4，本次不登录。'
    }
    if ($Html -match 'AccountFilter["'']\s*:\s*["''](?:tolower|toupper)["'']' -or
        $Html -match 'DialSwitch["'']\s*:\s*true') {
        throw 'MANUAL:公共区增加了账号转换或拨号要求，请手动确认。'
    }
    return [pscustomobject]@{ Ip = $ipText; AcId = $acid }
}

function Get-LoginContext($Status) {
    return ConvertFrom-SzuPage (Invoke-SzuRequest $script:PageUrl -PageRedirects).Text
}

function New-SrunParameters($Context, [Management.Automation.PSCredential]$Credential, [string]$Token) {
    if ($Token -notmatch '^[A-Fa-f0-9]{16,128}$') { throw '认证挑战值格式异常，本次不登录。' }
    $account = $Credential.UserName
    $password = $Credential.GetNetworkCredential().Password
    $json = [SzuSrunCodec]::BuildInfo($account, $password, $Context.Ip, $Context.AcId)
    $info = [SzuSrunCodec]::EncodeInfo($json, $Token)
    $digest = [SzuSrunCodec]::PasswordDigest($password, $Token)
    $checksum = [SzuSrunCodec]::Checksum($Token + $account + $Token + $digest + $Token + $Context.AcId + $Token + $Context.Ip + $Token + '200' + $Token + '1' + $Token + $info)
    return [ordered]@{
        action = 'login'; username = $account; password = '{MD5}' + $digest
        os = 'Windows NT'; name = 'Windows'; nas_ip = ''; double_stack = '0'
        chksum = $checksum; info = $info; ac_id = $Context.AcId; ip = $Context.Ip
        n = '200'; type = '1'; captchaId = ''; captchaVal = ''
    }
}

function Invoke-PortalLogin($Context, [Management.Automation.PSCredential]$Credential) {
    $captchaUrl = New-QueryUrl ($script:BaseUrl + '/v2/srun_portal_captcha_image_info') ([ordered]@{ user_name = $Credential.UserName; ip = $Context.Ip })
    $captchaResponse = Invoke-SzuRequest $captchaUrl -AllowNotFound
    if ($captchaResponse.Status -ne 404) {
        $captcha = ConvertFrom-PortalJson $captchaResponse.Text
        if ([string](Get-Field $captcha 'code' '') -ne '0' -or [string](Get-Field $captcha 'data' '') -notin @('0','1')) {
            throw '验证码状态无法确认，本次不登录。'
        }
        if ([string]$captcha.data -eq '1') { throw 'MANUAL:公共区要求验证码，请在浏览器完成验证。' }
    }
    $challenge = Invoke-PortalJson ($script:BaseUrl + '/cgi-bin/get_challenge') ([ordered]@{ username = $Credential.UserName; ip = $Context.Ip })
    if ([string](Get-Field $challenge 'error') -ne 'ok') { throw '认证挑战获取失败，稍后重试。' }
    $freshIp = [string](Get-Field $challenge 'client_ip' '')
    $address = $null
    if (-not [Net.IPAddress]::TryParse($freshIp, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $freshIp -eq '0.0.0.0') {
        throw '认证挑战未返回当前 IPv4，本次不登录。'
    }
    $freshContext = [pscustomobject]@{ Ip = $freshIp; AcId = $Context.AcId }
    $reply = Invoke-PortalJson ($script:BaseUrl + '/cgi-bin/srun_portal') (New-SrunParameters $freshContext $Credential ([string](Get-Field $challenge 'challenge')))
    if ([string](Get-Field $reply 'error') -eq 'ok') { return [pscustomobject]@{ result = 1 } }
    $errorName = [string](Get-Field $reply 'error')
    $message = [string](Get-Field $reply 'error_msg')
    $code = [string](Get-Field $reply 'ecode')
    if ($errorName -match 'vcode|captcha') { throw 'MANUAL:公共区要求验证码，请在浏览器完成验证。' }
    if ($errorName -match 'account_locked|user_must_modify_password') { throw 'MANUAL:账号被锁定或要求修改密码，请先打开网页处理。' }
    if ($code -eq 'E2553') { $message = '账号或密码错误' }
    if ($code -eq 'E2620') { $message = '在线设备数达到上限' }
    return [pscustomobject]@{ result = 0; msg = $message + ' ' + $errorName }
}

function Invoke-Diagnose {
    $status = Get-PortalStatus
    if ([string]$status.result -eq '1') { Write-Host '深大公共区 HTTPS 服务器可达，当前账号在线。'; return }
    $context = Get-LoginContext $status
    Write-Host ('深大公共区 HTTPS 与 SRun 页面正常，当前未认证；已识别接入控制器 ' + $context.AcId + '。')
    Write-Host '本次没有加载或提交校园网账号密码。'
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        switch ($Action) {
            'Menu' { Show-Menu }
            'Setup' { Set-Account }
            'Worker' { Invoke-Worker }
            'Once' { $cycle = Invoke-ConnectionCycle (Read-SavedCredential); Write-Host $cycle.Message }
            'Stop' { Stop-Worker }
            'Diagnose' { Invoke-Diagnose }
            'EnableStartup' { Set-Autostart $true }
            'DisableStartup' { Set-Autostart $false }
        }
    } catch { Write-Host ('操作未完成：' + $_.Exception.Message) -ForegroundColor Yellow; exit 1 }
}

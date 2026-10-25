#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu','Setup','Worker','Once','Stop','Diagnose','EnableStartup','DisableStartup')]
    [string]$Action = 'Menu'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:PortalHost = '172.30.255.42'
$script:AcIp = '172.30.255.41'
$script:BaseUrl = 'http://' + $script:PortalHost
# 不沿用分享链接里的 wlanuserip；每次都读取服务器返回的当前 IP。
$script:PageUrl = $script:BaseUrl + '/a79.htm?wlanacname=&wlanacip=' + $script:AcIp
$script:ApiUrl = $script:BaseUrl + ':801/eportal/portal/'
$script:DataDir = Join-Path $PSScriptRoot '.data'
$script:CredentialPath = Join-Path $script:DataDir 'credential.xml'
$script:PausePath = Join-Path $script:DataDir 'paused.txt'
$script:LogPath = Join-Path $script:DataDir 'reconnect.log'
$script:StatusPath = Join-Path $script:DataDir 'status.json'
$script:IntervalSeconds = 30
$script:TimeoutMilliseconds = 8000
$script:JsVersion = '4.1.3'
$script:StopSignal = $null

function Get-Field($Object, [string]$Name, $Default = '') {
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Initialize-DataDirectory {
    if (-not (Test-Path -LiteralPath $script:DataDir)) {
        $null = New-Item -ItemType Directory -Path $script:DataDir
    }
}

function Write-Event([string]$Message) {
    Initialize-DataDirectory
    # 日志只记录状态和经脱敏的提示，禁止写入请求 URL、账号、密码或完整响应。
    if ((Test-Path -LiteralPath $script:LogPath) -and
        (Get-Item -LiteralPath $script:LogPath).Length -gt 1048576) {
        Move-Item -LiteralPath $script:LogPath -Destination ($script:LogPath + '.old') -Force
    }
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    @{ time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); message = $Message } |
        ConvertTo-Json | Set-Content -LiteralPath $script:StatusPath -Encoding UTF8
}

function New-QueryUrl([string]$Base, [System.Collections.IDictionary]$Parameters) {
    $items = foreach ($entry in $Parameters.GetEnumerator()) {
        '{0}={1}' -f [Uri]::EscapeDataString([string]$entry.Key),
            [Uri]::EscapeDataString([string]$entry.Value)
    }
    return $Base + '?' + ($items -join '&')
}

function Assert-PortalUrl([string]$Url) {
    $target = [Uri]$Url
    if ($target.Scheme -ne 'http' -or $target.Host -ne $script:PortalHost -or
        $target.Port -notin @(80,801) -or $target.UserInfo -ne '') {
        throw '已阻止向非指定校园认证服务器发送请求。'
    }
}

function Invoke-PortalRequest([string]$Url) {
    if ($null -ne $script:StopSignal -and $script:StopSignal.WaitOne(0)) {
        throw 'STOP:后台检测正在停止。'
    }
    Assert-PortalUrl $Url
    $response = $null
    $stream = $null
    $memory = $null
    try {
        $request = [Net.HttpWebRequest]::Create($Url)
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.Timeout = $script:TimeoutMilliseconds
        $request.ReadWriteTimeout = $script:TimeoutMilliseconds
        $request.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
        $request.UserAgent = 'CampusAutoLogin/1.0 Windows'
        $request.Referer = $script:PageUrl
        $request.CachePolicy = New-Object Net.Cache.RequestCachePolicy([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw 'Unexpected HTTP response' }
        $stream = $response.GetResponseStream()
        $memory = New-Object IO.MemoryStream
        $buffer = New-Object byte[] 8192
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $count)
            if ($memory.Length -gt 2097152) { throw 'Response too large' }
        }
        $bytes = $memory.ToArray()
        # 此校园服务器有些静态文件直接返回 gzip 数据，但未设置 Content-Encoding。
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 31 -and $bytes[1] -eq 139) {
            $compressed = New-Object IO.MemoryStream(,$bytes)
            $gzip = New-Object IO.Compression.GZipStream($compressed, [IO.Compression.CompressionMode]::Decompress)
            $expanded = New-Object IO.MemoryStream
            try {
                while (($count = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $expanded.Write($buffer, 0, $count)
                    if ($expanded.Length -gt 2097152) { throw 'Response too large' }
                }
                $bytes = $expanded.ToArray()
            } finally { $gzip.Dispose(); $compressed.Dispose(); $expanded.Dispose() }
        }
        $charset = 'utf-8'
        if ($response.ContentType -match 'charset\s*=\s*["'']?([\w-]+)') {
            $charset = $Matches[1]
        } else {
            $prefix = [Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min(1024, $bytes.Length))
            if ($prefix -match 'charset\s*=\s*["'']?([\w-]+)') { $charset = $Matches[1] }
        }
        return [Text.Encoding]::GetEncoding($charset).GetString($bytes)
    } catch {
        # 异常对象可能包含带密码的 URL，绝不把原始异常向外传递。
        throw '校园认证服务器暂不可达或响应异常；请检查校园网连接。'
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

function ConvertFrom-PortalJson([string]$Text) {
    $body = $Text.Trim().TrimStart([char]0xFEFF)
    if ($body -notmatch '^\{') {
        $wrapper = [regex]::Match($body, '\A\s*[A-Za-z_$][\w$]*\s*\(\s*(\{.*\})\s*\)\s*;?\s*\z', 'Singleline')
        if (-not $wrapper.Success) { throw '认证接口返回的内容不是有效 JSON/JSONP。' }
        $body = $wrapper.Groups[1].Value
    }
    try { return ConvertFrom-Json -InputObject $body -ErrorAction Stop }
    catch { throw '认证接口的 JSON 数据无法解析。' }
}

function Invoke-PortalJson([string]$Base, [System.Collections.IDictionary]$Parameters) {
    $query = [ordered]@{ callback = 'campusCallback'; jsVersion = $script:JsVersion }
    foreach ($entry in $Parameters.GetEnumerator()) { $query[$entry.Key] = $entry.Value }
    return ConvertFrom-PortalJson (Invoke-PortalRequest (New-QueryUrl $Base $query))
}

function Get-PortalStatus {
    $status = Invoke-PortalJson ($script:BaseUrl + '/drcom/chkstatus') @{}
    if ([string](Get-Field $status 'result' 'unknown') -notin @('0','1')) {
        throw '认证状态未知，本次不提交账号密码。'
    }
    return $status
}

function Get-PageVariable([string]$Html, [string]$Name, [string]$Default = '') {
    $pattern = '\b' + [regex]::Escape($Name) + '\s*=\s*["'']([^"'']*)["'']'
    $match = [regex]::Match($Html, $pattern)
    if ($match.Success) { return $match.Groups[1].Value.Trim() }
    return $Default
}

function Get-LoginContext($Status) {
    $html = Invoke-PortalRequest $script:PageUrl
    if ($html -notmatch 'Dr\.COMWebLoginID_' -or $html -notmatch 'a41\.js') {
        throw 'MANUAL:认证页面已变化，请打开网页手动确认。'
    }
    $ipText = Get-PageVariable $html 'v46ip'
    if (-not $ipText) { $ipText = Get-PageVariable $html 'ss5' }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($ipText, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $ipText -eq '0.0.0.0') {
        throw '无法从认证页面获取当前电脑的 IPv4 地址，本次不登录。'
    }
    $mac = [string](Get-Field $Status 'ss4' (Get-PageVariable $html 'ss4' '000000000000'))
    $mac = $mac.Replace(':','').Replace('-','').Trim().ToUpperInvariant()
    if ($mac -notmatch '^[0-9A-F]{12}$') { throw '认证服务器返回的 MAC 格式异常。' }
    $vlan = Get-PageVariable $html 'vlanid' '0'
    $configReply = Invoke-PortalJson ($script:ApiUrl + 'page/loadConfig') ([ordered]@{
        program_index = ''; wlan_vlan_id = $vlan
        wlan_user_ip = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ipText))
        wlan_user_ipv6 = ''; wlan_user_ssid = ''; wlan_user_areaid = ''
        wlan_ac_ip = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:AcIp))
        wlan_ap_mac = '000000000000'; gw_id = '000000000000'
    })
    $config = Get-Field $configReply 'data' $null
    if ($null -eq $config) { throw '无法读取认证页面配置，本次不登录。' }
    $method = [string](Get-Field $config 'login_method' '')
    if ($method -notin @('1','9') -or [string](Get-Field $config 'register_mode' '') -ne '1' -or
        [string](Get-Field $config 'password_cut' '0') -ne '0') {
        throw 'MANUAL:认证方式发生变化，请手动登录；程序需要重新适配。'
    }
    $program = [string](Get-Field $config 'program_index')
    $page = [string](Get-Field $config 'page_index')
    if ($program -notmatch '^[A-Za-z0-9_-]{1,80}$' -or $page -notmatch '^[A-Za-z0-9_-]{1,80}$') {
        throw '认证页面配置异常，本次不登录。'
    }
    $template = Invoke-PortalRequest ($script:BaseUrl + ':801/eportal/extern/' + $program + '/' + $page + '/pc.js')
    if ($template -notmatch '<form\b' -or $template -notmatch 'name=["'']upass["'']') {
        throw 'MANUAL:登录表单已变化，请手动确认。'
    }
    foreach ($inputTag in [regex]::Matches($template, '<input\b[^>]*\bname\s*=\s*["'']captcha["''][^>]*>', 'IgnoreCase')) {
        if ($inputTag.Value -notmatch 'display\s*:\s*none' -and $inputTag.Value -notmatch '\bhidden(?:\s|=|>)') {
            throw 'MANUAL:页面要求验证码，请在浏览器中手动完成验证。'
        }
    }
    if ($template -match 'name=["''](?:ISP_select|ISP_radio|checkIOMode)["'']') {
        throw 'MANUAL:页面增加了运营商或模式选择，请手动登录后重新适配。'
    }
    return [pscustomobject]@{ Ip = $ipText; Mac = $mac; Config = $config; Method = $method }
}

function New-LoginParameters($Context, [Management.Automation.PSCredential]$Credential) {
    $account = $Credential.UserName
    $suffix = [string](Get-Field $Context.Config 'account_suffix' '')
    if ($suffix -and -not $account.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) { $account += $suffix }
    if ([string](Get-Field $Context.Config 'account_prefix' '0') -eq '1') {
        $prefix = ',0,'
        if ([string](Get-Field $Context.Config 'custom_perceive' '0') -eq '1') { $prefix = ',b,' }
        $account = $prefix + $account
    }
    return [ordered]@{
        login_method = $Context.Method; user_account = $account
        user_password = $Credential.GetNetworkCredential().Password
        wlan_user_ip = $Context.Ip; wlan_user_ipv6 = ''; wlan_user_mac = $Context.Mac
        wlan_ac_ip = $script:AcIp; wlan_ac_name = ''; terminal_type = '1'; lang = 'zh-cn'
    }
}

function Get-SafeLoginMessage($Reply, [Management.Automation.PSCredential]$Credential) {
    # 不保存服务器的原始提示：它可能回显账号、密码或请求 URL。
    $raw = [string](Get-Field $Reply 'msg' (Get-Field $Reply 'message' ''))
    $message = '认证未成功，请打开网页查看具体提示'
    if ($raw -match '验证码|captcha') { $message = '需要手动完成验证码' }
    elseif ($raw -match '短信|SMS') { $message = '需要手动完成短信验证' }
    elseif ($raw -match '欠费|停机|余额') { $message = '账号可能欠费或余额不足' }
    elseif ($raw -match '停用|禁用|disabled') { $message = '账号已停用，请联系学校网络服务' }
    elseif ($raw -match '上限|多终端|设备数|too many|limit') { $message = '在线设备数可能达到上限' }
    elseif ($raw -match '密码|password') { $message = '账号或密码未通过认证' }
    elseif ($raw -match '不存在|unknown user|not exist') { $message = '账号不存在或未开通' }
    $code = [string](Get-Field $Reply 'ret_code' '')
    if ($code -match '^\d{1,5}$') { $message += '（代码 ' + $code + '）' }
    return $message
}

function Invoke-PortalLogin($Context, [Management.Automation.PSCredential]$Credential) {
    return Invoke-PortalJson ($script:ApiUrl + 'login') (New-LoginParameters $Context $Credential)
}

function Invoke-ConnectionCycle([Management.Automation.PSCredential]$Credential) {
    $status = Get-PortalStatus
    if ([string]$status.result -eq '1') {
        return [pscustomobject]@{ Kind = 'Online'; Message = '校园网认证正常。' }
    }
    $context = Get-LoginContext $status
    $reply = Invoke-PortalLogin $context $Credential
    $result = [string](Get-Field $reply 'result' '')
    if ($result -in @('1','ok')) {
        # 登录返回成功仍需再查一次状态，避免把失败误报为已连接。
        $confirmed = Get-PortalStatus
        if ([string]$confirmed.result -eq '1') {
            return [pscustomobject]@{ Kind = 'Restored'; Message = '已自动重新登录，校园网认证恢复。' }
        }
        return [pscustomobject]@{ Kind = 'Rejected'; Message = '登录接口已受理，但尚未确认在线。' }
    }
    $message = Get-SafeLoginMessage $reply $Credential
    $kind = 'Rejected'
    if ($message -match '密码|password|验证码|短信|captcha|欠费|停用|停机|余额|不存在|上限|多终端|设备数') { $kind = 'Manual' }
    return [pscustomobject]@{ Kind = $kind; Message = $message }
}

function Get-CycleDecision($Cycle, [int]$PreviousRejections) {
    $rejections = 0
    $delay = $script:IntervalSeconds
    if ($Cycle.Kind -notin @('Online','Restored')) {
        $rejections = $PreviousRejections + 1
        $delay = [int][Math]::Min(900, 120 * [Math]::Pow(2, [Math]::Min(3, $rejections - 1)))
    }
    return [pscustomobject]@{
        Rejections = $rejections; Delay = $delay
        Pause = ($Cycle.Kind -eq 'Manual' -or $rejections -ge 3)
    }
}

function Get-InstanceId {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($PSScriptRoot.ToLowerInvariant() + $identity))
        return 'CampusAutoLogin-' + ([BitConverter]::ToString($bytes).Replace('-','').Substring(0,20))
    } finally { $hash.Dispose() }
}

function Read-SavedCredential {
    if (-not (Test-Path -LiteralPath $script:CredentialPath)) { throw '请先通过菜单 2 设置校园网账号密码。' }
    try {
        $credential = Import-Clixml -LiteralPath $script:CredentialPath
        if ($credential -isnot [Management.Automation.PSCredential]) { throw 'Invalid credential' }
        $null = $credential.GetNetworkCredential().Password
        return $credential
    } catch { throw '无法解密账号配置。请用本机当前 Windows 用户重新设置账号密码。' }
}

function Stop-Worker([switch]$Wait) {
    $signal = $null
    try {
        $signal = [Threading.EventWaitHandle]::OpenExisting('Local\' + (Get-InstanceId) + '-Stop')
        $null = $signal.Set()
        Write-Host '已发送停止信号，后台程序将在当前请求结束后退出。'
        if ($Wait) {
            $runningMutex = $null
            $acquired = $false
            try {
                $runningMutex = [Threading.Mutex]::OpenExisting('Local\' + (Get-InstanceId))
                try { $acquired = $runningMutex.WaitOne(15000) }
                catch [Threading.AbandonedMutexException] { $acquired = $true }
                if (-not $acquired) { throw '后台程序仍在退出，请稍后再修改账号。' }
            } finally {
                if ($acquired) { $runningMutex.ReleaseMutex() }
                if ($null -ne $runningMutex) { $runningMutex.Dispose() }
            }
        }
    } catch [Threading.WaitHandleCannotBeOpenedException] {
        Write-Host '当前没有运行中的后台程序。'
    } finally { if ($null -ne $signal) { $signal.Dispose() } }
}

function Set-Account {
    Write-Host "`n请输入和认证网页相同的本人账号密码；密码不会显示，也不会发送到聊天。"
    $account = (Read-Host '校园网账号（输入空行取消）').Trim()
    if (-not $account) { return }
    $password = Read-Host '校园网密码' -AsSecureString
    if ($password.Length -eq 0) { Write-Host '密码为空，已取消。'; return }
    Initialize-DataDirectory
    Stop-Worker -Wait
    $credential = New-Object Management.Automation.PSCredential($account, $password)
    $temporary = $script:CredentialPath + '.tmp'
    $credential | Export-Clixml -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $script:CredentialPath -Force
    if (Test-Path -LiteralPath $script:PausePath) { Remove-Item -LiteralPath $script:PausePath }
    Write-Host '已保存。密码使用 Windows DPAPI 加密；请通过菜单 1 启动。'
}

function Get-PowerShellPath {
    return Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
}

function Start-Worker {
    if (-not (Test-Path -LiteralPath $script:CredentialPath)) { Set-Account }
    if (-not (Test-Path -LiteralPath $script:CredentialPath)) { return }
    if (Test-Path -LiteralPath $script:PausePath) {
        Write-Host '认证重试已暂停。请查看日志，并通过菜单 2 检查、重新保存账号密码。'
        return
    }
    $null = Read-SavedCredential
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action Worker'
    $null = Start-Process -FilePath (Get-PowerShellPath) -ArgumentList $arguments -WindowStyle Hidden
    Write-Host '已启动后台检测，可以关闭这个菜单窗口。每 30 秒检查一次；菜单 3 可停止。'
}

function Set-Autostart([bool]$Enable) {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $name = Get-InstanceId
    if ($Enable) {
        $null = Read-SavedCredential
        $command = '"' + (Get-PowerShellPath) + '" -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action Worker'
        $null = New-ItemProperty -Path $key -Name $name -Value $command -PropertyType String -Force
        Write-Host '已启用：当前 Windows 用户登录后自动运行。请保持程序文件夹路径不变。'
    } else {
        if ($null -ne (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $key -Name $name
        }
        Write-Host '已取消登录 Windows 后自动运行。'
    }
}

function Invoke-Worker {
    Initialize-DataDirectory
    $id = Get-InstanceId
    $mutex = New-Object Threading.Mutex($false, ('Local\' + $id))
    $owned = $false
    $stop = $null
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { return }
        $stop = New-Object Threading.EventWaitHandle($false, [Threading.EventResetMode]::ManualReset, ('Local\' + $id + '-Stop'))
        $script:StopSignal = $stop
        $null = $stop.Reset()
        if (Test-Path -LiteralPath $script:PausePath) { Write-Event '自动登录已暂停，请通过菜单 2 重新设置账号。'; return }
        $credential = Read-SavedCredential
        $rejections = 0
        $networkErrors = 0
        $previous = ''
        Write-Event '后台检测已启动，每 30 秒查询一次认证状态。'
        do {
            $delay = $script:IntervalSeconds
            try {
                $cycle = Invoke-ConnectionCycle $credential
                $networkErrors = 0
                $decision = Get-CycleDecision $cycle $rejections
                $rejections = $decision.Rejections
                $delay = $decision.Delay
                if ($decision.Pause) {
                    $message = '自动登录已暂停：' + $cycle.Message + ' 请打开网页确认，并通过菜单 2 重新设置。'
                    Set-Content -LiteralPath $script:PausePath -Value $message -Encoding UTF8
                    Write-Event $message
                    break
                }
                if ($cycle.Message -ne $previous) { Write-Event $cycle.Message; $previous = $cycle.Message }
            } catch {
                # 只记录本程序生成的固定提示，不输出异常堆栈、原始请求或凭据。
                $message = [string]$_.Exception.Message
                if ($message.StartsWith('STOP:') -or $stop.WaitOne(0)) { break }
                if ($message.StartsWith('MANUAL:')) {
                    $message = $message.Substring(7)
                    Set-Content -LiteralPath $script:PausePath -Value $message -Encoding UTF8
                    Write-Event ('自动登录已暂停：' + $message)
                    break
                }
                $networkErrors++
                $delay = [int][Math]::Min(300, 30 * [Math]::Pow(2, [Math]::Min(4, $networkErrors - 1)))
                $message = '连接或认证状态暂时无法确认，稍后自动重试。'
                if ($message -ne $previous) { Write-Event $message; $previous = $message }
            }
        } while (-not $stop.WaitOne($delay * 1000))
        if (-not (Test-Path -LiteralPath $script:PausePath)) { Write-Event '后台检测已停止。' }
    } catch {
        Write-Event '后台程序无法继续运行。请打开菜单，检查账号配置及文件夹写入权限。'
    } finally {
        $script:StopSignal = $null
        if ($null -ne $stop) { $stop.Dispose() }
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Invoke-Diagnose {
    $status = Get-PortalStatus
    if ([string]$status.result -eq '1') { Write-Host '服务器可达，当前校园网认证已登录。'; return }
    $context = Get-LoginContext $status
    Write-Host ('服务器可达，当前未登录；已识别当前 IP：' + $context.Ip + '，账号密码认证接口正常。')
    Write-Host '此检测没有提交账号密码。'
}

function Show-Menu {
    while ($true) {
        Write-Host "`n========== 校园网自动重连 =========="
        if (Test-Path -LiteralPath $script:StatusPath) {
            try {
                $last = Get-Content -LiteralPath $script:StatusPath -Raw -Encoding UTF8 | ConvertFrom-Json
                Write-Host ('最近记录：' + $last.time + '  ' + $last.message)
            } catch { }
        }
        Write-Host '1. 启动后台自动重连（首次会要求设置账号）'
        Write-Host '2. 设置或修改账号密码'
        Write-Host '3. 停止后台检测'
        Write-Host '4. 查看最近日志'
        Write-Host '5. 开启登录 Windows 后自动运行'
        Write-Host '6. 取消自动运行'
        Write-Host '7. 检测当前认证状态（不提交账号密码）'
        Write-Host '8. 打开校园网认证网页'
        Write-Host '0. 关闭菜单'
        $choice = Read-Host '请输入数字'
        try {
            switch ($choice) {
                '1' { Start-Worker }
                '2' { Set-Account }
                '3' { Stop-Worker }
                '4' {
                    if (Test-Path -LiteralPath $script:LogPath) { Get-Content -LiteralPath $script:LogPath -Tail 25 -Encoding UTF8 | Out-Host }
                    else { Write-Host '还没有日志。' }
                }
                '5' { Set-Autostart $true }
                '6' { Set-Autostart $false }
                '7' { Invoke-Diagnose }
                '8' { $null = Start-Process $script:PageUrl }
                '0' { return }
                default { Write-Host '请输入菜单中的数字。' }
            }
        } catch { Write-Host ('操作未完成：' + $_.Exception.Message) -ForegroundColor Yellow }
    }
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

<#
.SYNOPSIS
    YZHY FPS PSW — Premium Boost • MAX FPS (PowerShell Edition)
    Uso rapido:  irm https://seulink.com/loader.ps1 | iex
.DESCRIPTION
    Otimizador completo de Windows para gaming com interface grafica WPF.
    Mesmo conjunto de otimizacoes da versao WPF/C#.
.NOTES
    Requer: Windows 10/11, PowerShell 5.1+
    Recomendado: Executar como Administrador
#>

# ==================== BOOTSTRAP ====================
# TLS 1.2 obrigatorio para downloads HTTPS (logos, irm, etc.)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ==================== VERIFICACAO ADMIN ====================
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Auto-elevacao: se executado como arquivo (.ps1) sem admin, relanca elevado
if (-not $script:IsAdmin -and $MyInvocation.MyCommand.Path) {
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs -ErrorAction Stop
        exit
    } catch {
        # UAC negado — continua sem admin (a UI exibe aviso)
    }
}

# ==================== FUNCOES DE OTIMIZACAO ====================

function Write-Log {
    param([string]$Message)
    $script:LogMessages += "$(Get-Date -Format 'HH:mm:ss') - $Message`n"
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Log "Erro ao definir registro: $Path\$Name - $_"
        return $false
    }
}

function Run-Hidden {
    param([string]$Exe, [string]$Args)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = $Args
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        # NAO redirecionar stdout/stderr: redirecionar sem ler causa deadlock no
        # .NET Framework (buffer cheio bloqueia o processo filho e WaitForExit trava infinitamente)
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($p) {
            $exited = $p.WaitForExit(20000)
            if (-not $exited) {
                try { $p.Kill() } catch {}
            }
        }
        return $true
    } catch {
        Write-Log "Erro ao executar: $Exe $Args - $_"
        return $false
    }
}

function Invoke-UIFlush {
    # DoEvents para WPF: processa eventos de render/input pendentes sem sair da thread UI
    try {
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        $cb = [System.Windows.Threading.DispatcherOperationCallback]{ param($f); $f.Continue = $false; $null }
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
            [System.Windows.Threading.DispatcherPriority]::Background, $cb, $frame) | Out-Null
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    } catch {}
}

function Delete-FilesSafe {
    param([string]$Path)
    $count = 0
    if (Test-Path $Path) {
        # Iteracao nao-recursiva no topo: Remove-Item -Recurse cuida das subpastas.
        # A cada 25 itens removidos chamamos Invoke-UIFlush para manter a UI responsiva.
        Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop; $count++ } catch {}
            if (($count % 25) -eq 0) { Invoke-UIFlush }
        }
    }
    return $count
}

# =============== SISTEMA ===============

function Invoke-CleanTemp {
    param([bool]$Enable)
    if (-not $Enable) { return "Limpeza de temporarios so executa quando ativada." }
    $temp    = $env:TEMP
    $winTemp = "$env:SystemRoot\Temp"
    $prefetch = "$env:SystemRoot\Prefetch"
    $removed = 0
    Set-PopupStep "Limpando: $temp"
    $removed += Delete-FilesSafe $temp
    Set-PopupStep "Limpando: $winTemp"
    $removed += Delete-FilesSafe $winTemp
    Set-PopupStep "Limpando: Prefetch"
    $removed += Delete-FilesSafe $prefetch
    return "Limpeza concluida. Itens removidos: $removed"
}

function Invoke-OptimizeServices {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para otimizar servicos." }

    $services = @(
        @{ Name="SysMain";            Desc="SysMain (Superfetch)" }
        @{ Name="DiagTrack";          Desc="DiagTrack (Telemetria)" }
        @{ Name="dmwappushservice";   Desc="dmwappushservice" }
        @{ Name="WSearch";            Desc="Windows Search" }
        @{ Name="wscsvc";             Desc="Windows Security Center" }
        @{ Name="WerSvc";             Desc="Windows Error Reporting" }
        @{ Name="BITS";               Desc="BITS (Background Transfer)" }
    )

    $count   = 0
    $total   = $services.Count
    $current = 0

    foreach ($svc in $services) {
        $current++
        $n = $svc.Name
        $d = $svc.Desc
        Set-PopupStep "$( if($Enable){ 'Desativando' } else { 'Restaurando' } ): $d"
        Set-PopupProgress ($current / ($total + 1))
        try {
            $svcObj = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($svcObj) {
                if ($Enable) {
                    # Stop first with short wait, then config — avoids hanging on slow services
                    if ($svcObj.Status -ne 'Stopped') {
                        $svcObj.Stop()
                        $svcObj.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(5))
                    }
                    Set-Service -Name $n -StartupType Disabled -ErrorAction SilentlyContinue
                } else {
                    $startType = switch ($n) {
                        "SysMain"          { "Manual" }
                        "DiagTrack"        { "Automatic" }
                        "WSearch"          { "Automatic" }
                        default            { "Manual" }
                    }
                    Set-Service -Name $n -StartupType $startType -ErrorAction SilentlyContinue
                    if ($n -notin @('DiagTrack','dmwappushservice')) {
                        Start-Service -Name $n -ErrorAction SilentlyContinue
                    }
                }
                $count++
            }
        } catch {}
    }
    Set-PopupProgress 1.0
    return if ($Enable) { "Servicos otimizados ($count/$total ajustados)" } else { "Servicos restaurados ao padrao" }
}

function Invoke-DefragDisk {
    param([bool]$Enable)
    Set-PopupStep "Executando: defrag C: /O"
    Run-Hidden "defrag" "C: /O" | Out-Null
    return "Desfragmentacao/otimizacao iniciada para C:"
}

function Invoke-CleanRegistry {
    param([bool]$Enable)
    Set-PopupStep "Executando: DISM cleanup-image"
    Run-Hidden "dism" "/online /cleanup-image /startcomponentcleanup" | Out-Null
    return "Limpeza de componentes do sistema executada (DISM)"
}

function Invoke-DisableAnimations {
    param([bool]$Enable)
    $val = if ($Enable) { 2 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" $val
    if ($Enable) {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 0 /f'
    } else {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9e3e078012000000 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 1 /f'
    }
    return if ($Enable) { "Animacoes e efeitos visuais desabilitados" } else { "Efeitos visuais restaurados" }
}

function Invoke-SetMaxPowerPlan {
    param([bool]$Enable)
    $guid = if ($Enable) { "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" } else { "381b4222-f694-41f0-9685-ff5bb260df2e" }
    Run-Hidden "powercfg" "/setactive $guid"
    return if ($Enable) { "Plano de energia: Alto desempenho" } else { "Plano de energia: Equilibrado" }
}

function Invoke-PrefetchSuperfetch {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 3 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" $val
    if ($script:IsAdmin) {
        $startVal = if ($Enable) { 4 } else { 2 }
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" "Start" $startVal
        if ($Enable) { Run-Hidden "sc" "stop SysMain" } else { Run-Hidden "sc" "start SysMain" }
    }
    return if ($Enable) { "Prefetch/SysMain desativados (otimizado para gaming)" } else { "Prefetch/SysMain restaurados" }
}

function Invoke-DisableTelemetry {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 3 }
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`" /v AllowTelemetry /t REG_DWORD /d $val /f"
    if ($script:IsAdmin) {
        if ($Enable) {
            Run-Hidden "sc" "config DiagTrack start= disabled"
            Run-Hidden "sc" "stop DiagTrack"
        } else {
            Run-Hidden "sc" "config DiagTrack start= auto"
            Run-Hidden "sc" "start DiagTrack"
        }
    }
    return if ($Enable) { "Telemetria reduzida" } else { "Telemetria restaurada" }
}

function Invoke-DisableTransparency {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`" /v EnableTransparency /t REG_DWORD /d $val /f"
    return if ($Enable) { "Transparencia desativada" } else { "Transparencia ativada" }
}

function Invoke-UltimatePerformance {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "powercfg" "/duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61"
        Run-Hidden "powercfg" "/setactive e9a42b02-d5df-448d-aa00-03f14749eb61"
        return "Plano Ultimate Performance ativo"
    } else {
        Run-Hidden "powercfg" "/setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        return "Plano Alto Desempenho ativo"
    }
}

function Invoke-DisableConsumerFeatures {
    param([bool]$Enable)
    if ($script:IsAdmin) {
        $val = if ($Enable) { 1 } else { 0 }
        Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`" /v DisableWindowsConsumerFeatures /t REG_DWORD /d $val /f"
    }
    return if ($Enable) { "Recursos de consumidor desativados" } else { "Recursos de consumidor restaurados" }
}

function Invoke-DisableCortana {
    param([bool]$Enable)
    if ($script:IsAdmin) {
        $val = if ($Enable) { 0 } else { 1 }
        Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search`" /v AllowCortana /t REG_DWORD /d $val /f"
    }
    return if ($Enable) { "Cortana desativada" } else { "Cortana ativada" }
}

function Invoke-DisableFeedback {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Siuf\Rules`" /v NumberOfSIUFInPeriod /t REG_DWORD /d $val /f"
    if ($script:IsAdmin) {
        $dVal = if ($Enable) { 1 } else { 0 }
        Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`" /v DoNotShowFeedbackNotifications /t REG_DWORD /d $dVal /f"
    }
    return if ($Enable) { "Notificacoes de feedback desativadas" } else { "Notificacoes de feedback restauradas" }
}

function Invoke-MenuDelayFast {
    param([bool]$Enable)
    $val = if ($Enable) { "0" } else { "400" }
    Run-Hidden "reg" "add `"HKCU\Control Panel\Desktop`" /v MenuShowDelay /t REG_SZ /d $val /f"
    return if ($Enable) { "Abertura de menus acelerada" } else { "Abertura de menus padrao" }
}

function Invoke-DisableStickyKeys {
    param([bool]$Enable)
    $stickyFlags = if ($Enable) { "506" } else { "510" }
    $filterFlags = if ($Enable) { "122" } else { "126" }
    $toggleFlags = if ($Enable) { "58" } else { "62" }
    Run-Hidden "reg" "add `"HKCU\Control Panel\Accessibility\StickyKeys`" /v Flags /t REG_SZ /d $stickyFlags /f"
    Run-Hidden "reg" "add `"HKCU\Control Panel\Accessibility\FilterKeys`" /v Flags /t REG_SZ /d $filterFlags /f"
    Run-Hidden "reg" "add `"HKCU\Control Panel\Accessibility\ToggleKeys`" /v Flags /t REG_SZ /d $toggleFlags /f"
    return if ($Enable) { "Sticky/Filter/Toggle Keys desativados" } else { "Sticky/Filter/Toggle Keys restaurados" }
}

function Invoke-DisableBackgroundApps {
    param([bool]$Enable)
    $val = if ($Enable) { 1 } else { 0 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications`" /v GlobalUserDisabled /t REG_DWORD /d $val /f"
    if ($script:IsAdmin) {
        $aVal = if ($Enable) { 2 } else { 0 }
        Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy`" /v LetAppsRunInBackground /t REG_DWORD /d $aVal /f"
    }
    return if ($Enable) { "Apps em segundo plano bloqueados" } else { "Apps em segundo plano permitidos" }
}

function Invoke-StartupDelayZero {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 500 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize`" /v StartupDelayInMSec /t REG_DWORD /d $val /f"
    return if ($Enable) { "Atraso de inicializacao removido" } else { "Atraso de inicializacao restaurado" }
}

function Invoke-TaskbarNewsOff {
    param([bool]$Enable)
    $val = if ($Enable) { 2 } else { 0 }
    # Windows 10: News & Interests
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds`" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d $val /f"
    if ($script:IsAdmin) {
        $eVal = if ($Enable) { 0 } else { 1 }
        Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds`" /v EnableFeeds /t REG_DWORD /d $eVal /f"
    }
    # Windows 11: Widgets (TaskbarDa = 0 oculta)
    $wVal = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarDa" $wVal
    if ($script:IsAdmin) {
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" $wVal
    }
    return if ($Enable) { "Noticias/Widgets ocultos (Win10 + Win11)" } else { "Noticias/Widgets exibidos" }
}

function Invoke-DisableCompatAssistant {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar Compat Assistant." }
    $val = if ($Enable) { 1 } else { 0 }
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat`" /v DisablePCA /t REG_DWORD /d $val /f"
    if ($Enable) { Run-Hidden "sc" "config PcaSvc start= disabled"; Run-Hidden "sc" "stop PcaSvc" }
    else { Run-Hidden "sc" "config PcaSvc start= demand"; Run-Hidden "sc" "start PcaSvc" }
    return if ($Enable) { "Compat Assistant desativado" } else { "Compat Assistant restaurado" }
}

function Invoke-DisableChromeTelemetry {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Run-Hidden "reg" "add `"HKCU\Software\Policies\Google\Chrome`" /v MetricsReportingEnabled /t REG_DWORD /d $val /f"
    Run-Hidden "reg" "add `"HKCU\Software\Policies\Google\Chrome`" /v CrashSendingEnabled /t REG_DWORD /d $val /f"
    return if ($Enable) { "Telemetria do Chrome bloqueada" } else { "Telemetria do Chrome restaurada" }
}

function Invoke-DisableNvidiaTelemetry {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para desativar telemetria NVIDIA." }
    if ($Enable) {
        Run-Hidden "sc" "config NvTelemetryContainer start= disabled"
        Run-Hidden "sc" "stop NvTelemetryContainer"
    } else {
        Run-Hidden "sc" "config NvTelemetryContainer start= demand"
        Run-Hidden "sc" "start NvTelemetryContainer"
    }
    return if ($Enable) { "Telemetria NVIDIA desativada" } else { "Telemetria NVIDIA restaurada" }
}

function Invoke-DisableOfficeTelemetry {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" "enabled" $val
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" "surveyenabled" $val
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm" "enablelogging" $val
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\osm" "enableupload" $val
    return if ($Enable) { "Telemetria do Office desativada" } else { "Telemetria do Office restaurada" }
}

function Invoke-DisableFirefoxTelemetry {
    param([bool]$Enable)
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Mozilla\Firefox" "DisableTelemetry" $val
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Mozilla\Firefox" "DisableFirefoxStudies" $val
    return if ($Enable) { "Telemetria do Firefox desativada" } else { "Telemetria do Firefox restaurada" }
}

function Invoke-DisableWifiSense {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar Wi-Fi Sense." }
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "WiFiSenseAllowed" $val
    return if ($Enable) { "Wi-Fi Sense desativado" } else { "Wi-Fi Sense restaurado" }
}

function Invoke-DisableSystemRestore {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar System Restore." }
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" "DisableSR" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" "DisableConfig" $val
    if ($Enable) { Disable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue }
    else { Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue }
    return if ($Enable) { "System Restore desativado" } else { "System Restore reativado" }
}

function Invoke-DisablePerformanceThrottle {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para ajustar Power Throttling." }
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" $val
    return if ($Enable) { "Power Throttling desativado" } else { "Power Throttling restaurado" }
}

function Invoke-DisableSpectrePatch {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar mitigacao Spectre/Meltdown." }
    if ($Enable) {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" 3
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" 3
    } else {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Spectre/Meltdown mitigations desativadas (requer reinicio)" } else { "Mitigacoes reativadas (requer reinicio)" }
}

function Invoke-DisableRemoteAssistance {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" $val
    return if ($Enable) { "Remote Assistance desativada" } else { "Remote Assistance restaurada" }
}

function Invoke-DisableWindowsTips {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" $val
    return if ($Enable) { "Windows Tips desativadas" } else { "Windows Tips restauradas" }
}

function Invoke-DisableLocationServices {
    param([bool]$Enable)
    $val = if ($Enable) { "Deny" } else { "Allow" }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" $val "String"
    return if ($Enable) { "Location Services desativados" } else { "Location Services restaurados" }
}

function Invoke-DisableActivityHistory {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" $val
    return if ($Enable) { "Activity History desativado" } else { "Activity History restaurado" }
}

function Invoke-DisableClipboardHistory {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory" $val
    return if ($Enable) { "Clipboard History desativado" } else { "Clipboard History restaurado" }
}

function Invoke-DisableAdvertisingId {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" $val
    return if ($Enable) { "Advertising ID desativado" } else { "Advertising ID restaurado" }
}

function Invoke-DisableDriverUpdates {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ExcludeWUDriversInQualityUpdate" $val
    return if ($Enable) { "Driver Updates via WU bloqueados" } else { "Driver Updates restaurados" }
}

# =============== GAMES ===============

function Invoke-GameMode {
    param([bool]$Enable)
    $val = if ($Enable) { 1 } else { 0 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\GameBar`" /v AutoGameModeEnabled /t REG_DWORD /d $val /f"
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\GameBar`" /v AllowAutoGameMode /t REG_DWORD /d $val /f"
    if ($Enable) {
        Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR`" /v AppCaptureEnabled /t REG_DWORD /d 0 /f"
        Run-Hidden "reg" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR`" /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f"
    }
    return if ($Enable) { "Game Mode habilitado com otimizacoes extras" } else { "Game Mode desabilitado" }
}

function Invoke-DisableGameDvr {
    param([bool]$Enable)
    $d = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" $d
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_Enabled" $d
    if ($script:IsAdmin) {
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" $d
    }
    return if ($Enable) { "Game DVR desativado" } else { "Game DVR ativado" }
}

function Invoke-DisableXboxGameBar {
    param([bool]$Enable)
    $d = if ($Enable) { 0 } else { 1 }
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\GameBar`" /v EnableGameBar /t REG_DWORD /d $d /f"
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\GameBar`" /v GameBarEnabled /t REG_DWORD /d $d /f"
    Run-Hidden "reg" "add `"HKCU\Software\Microsoft\GameBar`" /v ShowStartupPanel /t REG_DWORD /d $d /f"
    return if ($Enable) { "Xbox Game Bar desativada" } else { "Xbox Game Bar ativada" }
}

function Invoke-FullscreenOptimization {
    param([bool]$Enable)
    $val = if ($Enable) { 2 } else { 0 }
    Run-Hidden "reg" "add `"HKCU\System\GameConfigStore`" /v GameDVR_FSEBehavior /t REG_DWORD /d $val /f"
    return if ($Enable) { "Otimizacao de tela cheia desativada" } else { "Otimizacao de tela cheia ativada" }
}

function Invoke-DisableXboxServices {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $services = @("XboxGipSvc", "XboxNetApiSvc")
    foreach ($svc in $services) {
        if ($Enable) {
            Run-Hidden "sc" "config $svc start= disabled"
            Run-Hidden "sc" "stop $svc"
        } else {
            Run-Hidden "sc" "config $svc start= demand"
            Run-Hidden "sc" "start $svc"
        }
    }
    return if ($Enable) { "Servicos Xbox desativados" } else { "Servicos Xbox ajustados" }
}

function Invoke-OptimizeGamesSystemProfile {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $resp = if ($Enable) { 0 } else { 20 }
    $gpuP = if ($Enable) { 8 } else { 2 }
    $pri = if ($Enable) { 6 } else { 2 }
    $sched = if ($Enable) { "High" } else { "Medium" }
    $sfio = if ($Enable) { "High" } else { "Normal" }
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile`" /v SystemResponsiveness /t REG_DWORD /d $resp /f"
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games`" /v `"GPU Priority`" /t REG_DWORD /d $gpuP /f"
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games`" /v Priority /t REG_DWORD /d $pri /f"
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games`" /v `"Scheduling Category`" /t REG_SZ /d $sched /f"
    Run-Hidden "reg" "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games`" /v `"SFIO Priority`" /t REG_SZ /d $sfio /f"
    return if ($Enable) { "Perfil do sistema ajustado para jogos" } else { "Perfil de jogos restaurado" }
}

function Invoke-FpsBoost {
    param([bool]$Enable)
    Set-PopupStep "Plano de energia maximo"
    Invoke-SetMaxPowerPlan $Enable
    Set-PopupStep "Desativando Game DVR"
    Invoke-DisableGameDvr $Enable
    Set-PopupStep "Desativando Xbox Game Bar"
    Invoke-DisableXboxGameBar $Enable
    Set-PopupStep "Perfil de sistema para jogos"
    Invoke-OptimizeGamesSystemProfile $Enable
    Set-PopupStep "Fullscreen Optimization"
    Invoke-FullscreenOptimization $Enable
    Set-PopupStep "Desativando throttling de rede"
    Invoke-DisableNetworkThrottling $Enable
    return if ($Enable) { "FPS Boost COMPLETO aplicado" } else { "FPS Boost revertido" }
}

function Invoke-UltraGamingMode {
    param([bool]$Enable)
    Set-PopupStep "Game Mode"
    Invoke-GameMode $Enable
    Set-PopupStep "Desativando Game DVR"
    Invoke-DisableGameDvr $Enable
    Set-PopupStep "Desativando Xbox Game Bar"
    Invoke-DisableXboxGameBar $Enable
    Set-PopupStep "Perfil de sistema para jogos"
    Invoke-OptimizeGamesSystemProfile $Enable
    Set-PopupStep "Desativando throttling de rede"
    Invoke-DisableNetworkThrottling $Enable
    Set-PopupStep "Fullscreen Optimization"
    Invoke-FullscreenOptimization $Enable
    Set-PopupStep "Plano Ultimate Performance"
    Invoke-UltimatePerformance $Enable
    Set-PopupStep "Desativando servicos Xbox"
    Invoke-DisableXboxServices $Enable
    Set-PopupStep "Desativando animacoes"
    Invoke-DisableAnimations $Enable
    return if ($Enable) { "Ultra Gaming Mode COMPLETO aplicado (9 otimizacoes)" } else { "Ultra Gaming Mode revertido" }
}

function Invoke-MasterGamingOptimization {
    param([bool]$Enable)
    Set-PopupStep "Aplicando Ultra Gaming Mode..."
    Invoke-UltraGamingMode $Enable
    Set-PopupStep "Desativando telemetria"
    Invoke-DisableTelemetry $Enable
    Set-PopupStep "Otimizando Prefetch/Superfetch"
    Invoke-PrefetchSuperfetch $Enable
    return if ($Enable) { "Master Gaming Optimization aplicado" } else { "Master Gaming Optimization revertido" }
}

function Invoke-OptimizeMmcss {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 0 } else { 20 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" $val
    $noLazy = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NoLazyMode" $noLazy
    return if ($Enable) { "MMCSS otimizado" } else { "MMCSS restaurado" }
}

function Invoke-OptimizeGpuThreadPriority {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 8 } else { 2 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "GPU Priority" $val
    return if ($Enable) { "GPU Thread Priority aumentada" } else { "GPU Thread Priority padrao" }
}

function Invoke-DisableDefenderRealtime {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "powershell" "-Command Set-MpPreference -DisableRealtimeMonitoring `$true"
    } else {
        Run-Hidden "powershell" "-Command Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    return if ($Enable) { "Defender Realtime pausado (ATENCAO!)" } else { "Defender Realtime restaurado" }
}

# =============== GAME BOOST (jogos especificos) ===============

function Invoke-ValorantBoost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-DisableXboxGameBar $Enable
    Invoke-FullscreenOptimization $Enable
    Invoke-DisableNetworkThrottling $Enable
    Invoke-OptimizeGamesSystemProfile $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT-Win64-Shipping.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    }
    return if ($Enable) { "Valorant Boost COMPLETO aplicado" } else { "Valorant Boost revertido" }
}

function Invoke-FortniteBoost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-DisableXboxGameBar $Enable
    Invoke-FullscreenOptimization $Enable
    Invoke-DisableNetworkThrottling $Enable
    Invoke-OptimizeGamesSystemProfile $Enable
    Invoke-UltimatePerformance $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    }
    return if ($Enable) { "Fortnite Boost COMPLETO aplicado" } else { "Fortnite Boost revertido" }
}

function Invoke-FiveMBoost {
    param([bool]$Enable)
    Invoke-UltraGamingMode $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GTA5.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM_GTAProcess.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    }
    return if ($Enable) { "FiveM/GTA Boost COMPLETO aplicado" } else { "FiveM/GTA Boost revertido" }
}

function Invoke-MinecraftBoost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-UltimatePerformance $Enable
    $val = if ($Enable) { 0 } else { 3 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" $val
    return if ($Enable) { "Minecraft Boost COMPLETO aplicado" } else { "Minecraft Boost revertido" }
}

function Invoke-RobloxBoost {
    param([bool]$Enable)
    Invoke-GameMode $Enable
    Invoke-DisableGameDvr $Enable
    Invoke-DisableNetworkThrottling $Enable
    return if ($Enable) { "Roblox Boost COMPLETO aplicado" } else { "Roblox Boost revertido" }
}

# =============== BOOSTER ===============

function Invoke-CpuBoost {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para otimizar CPU." }
    Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN $(if ($Enable) { 100 } else { 5 })"
    Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PERFBOOSTMODE $(if ($Enable) { 2 } else { 0 })"
    Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PERFBOOSTPOL $(if ($Enable) { 100 } else { 50 })"
    Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PERFINCPOL $(if ($Enable) { 2 } else { 0 })"
    Run-Hidden "powercfg" "/setactive scheme_current"
    return if ($Enable) { "CPU Boost aplicado (min 100%, turbo agressivo)" } else { "CPU restaurada ao padrao" }
}

function Invoke-RamCleaner {
    param([bool]$Enable)
    if (-not $Enable) { return "RAM Cleaner executa apenas quando ativado." }
    Set-PopupStep "Compactando working sets de processos..."
    if ($script:IsAdmin) {
        try {
            if (-not ([System.Management.Automation.PSTypeName]'RamHelper').Type) {
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class RamHelper {
    [DllImport("kernel32.dll")]
    public static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);
}
"@ -ErrorAction SilentlyContinue
            }
            Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                try { [RamHelper]::SetProcessWorkingSetSize($_.Handle, [IntPtr](-1), [IntPtr](-1)) | Out-Null } catch {}
            }
        } catch {}
    }
    Set-PopupStep "Executando ProcessIdleTasks..."
    Run-Hidden "rundll32.exe" "advapi32.dll,ProcessIdleTasks"
    [System.GC]::Collect()
    return "RAM liberada (working sets compactados em todos os processos)"
}

function Invoke-GpuOptimize {
    param([bool]$Enable)
    if ($Enable) {
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;" "String"
        # GPU max performance no power plan
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 1"
            Run-Hidden "powercfg" "/setactive scheme_current"
        }
    } else {
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=0;" "String"
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 0"
            Run-Hidden "powercfg" "/setactive scheme_current"
        }
    }
    return if ($Enable) { "GPU otimizada (VRR + SwapEffect + Max Perf)" } else { "GPU restaurada" }
}

function Invoke-DisableSearchIndex {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "sc" "config WSearch start= disabled"
        Run-Hidden "sc" "stop WSearch"
    } else {
        Run-Hidden "sc" "config WSearch start= delayed-auto"
        Run-Hidden "sc" "start WSearch"
    }
    return if ($Enable) { "Indexacao desativada" } else { "Indexacao restaurada" }
}

function Invoke-DisablePrintSpooler {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "sc" "config Spooler start= disabled"
        Run-Hidden "sc" "stop Spooler"
    } else {
        Run-Hidden "sc" "config Spooler start= auto"
        Run-Hidden "sc" "start Spooler"
    }
    return if ($Enable) { "Spooler de impressao desativado" } else { "Spooler restaurado" }
}

function Invoke-RemoveApps {
    param([bool]$Enable)
    if (-not $Enable) { return "Remocao de apps executa apenas quando ativada." }
    $bloatware = @(
        "Microsoft.BingWeather", "Microsoft.GetHelp", "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.People", "Microsoft.WindowsFeedbackHub", "Microsoft.Xbox*",
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.YourPhone",
        "Microsoft.MixedReality.Portal", "Microsoft.SkypeApp"
    )
    $count = 0
    foreach ($app in $bloatware) {
        try {
            Get-AppxPackage -Name $app -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
            $count++
        } catch {}
    }
    return "Bloatware removido ($count apps processados)"
}

function Invoke-CleanBrowserCache {
    param([bool]$Enable)
    if (-not $Enable) { return "Limpeza de cache executa apenas quando ativada." }
    $removed = 0
    $removed += Delete-FilesSafe "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    $removed += Delete-FilesSafe "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    $removed += Delete-FilesSafe "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    return "Cache de navegadores limpo. Itens removidos: $removed"
}

function Invoke-CleanPrefetch {
    param([bool]$Enable)
    if (-not $Enable) { return "Limpeza de prefetch executa apenas quando ativada." }
    $removed = Delete-FilesSafe "$env:SystemRoot\Prefetch"
    return "Prefetch limpo. Itens removidos: $removed"
}

function Invoke-DeepClean {
    param([bool]$Enable)
    if (-not $Enable) { return "Limpeza profunda executa apenas quando ativada." }
    Run-Hidden "dism" "/online /cleanup-image /startcomponentcleanup"
    Run-Hidden "cleanmgr" "/d C /sagerun:1"
    return "Limpeza profunda executada"
}

function Invoke-RemoveOldDrivers {
    param([bool]$Enable)
    if (-not $Enable) { return "Limpeza de drivers nao executada." }
    if (-not $script:IsAdmin) { return "Requer administrador para remover drivers." }
    Set-PopupStep "Listando drivers duplicados/obsoletos..."
    $count = 0
    try {
        # Remove drivers nao ativos (staged mas nao em uso)
        $output = & pnputil /enum-drivers 2>$null
        $oemFiles = ($output | Select-String 'Published Name\s+:\s+(oem\d+\.inf)' | ForEach-Object { $_.Matches[0].Groups[1].Value })
        foreach ($inf in $oemFiles) {
            $result = & pnputil /delete-driver $inf 2>$null
            if ($LASTEXITCODE -eq 0) { $count++; Set-PopupStep "Removido: $inf" }
        }
    } catch {}
    return "Drivers obsoletos removidos: $count"
}

function Invoke-DisableHibernation {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) { Run-Hidden "powercfg" "/hibernate off" }
    else { Run-Hidden "powercfg" "/hibernate on" }
    return if ($Enable) { "Hibernacao desativada (hiberfil.sys removido)" } else { "Hibernacao ativada" }
}

function Invoke-DisableFastStartup {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" $val
    return if ($Enable) { "Fast Startup desativado" } else { "Fast Startup ativado" }
}

function Invoke-OptimizeNtfs {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "fsutil" "behavior set disablelastaccess 1"
        Run-Hidden "fsutil" "behavior set disable8dot3 1"
    } else {
        Run-Hidden "fsutil" "behavior set disablelastaccess 0"
        Run-Hidden "fsutil" "behavior set disable8dot3 0"
    }
    return if ($Enable) { "NTFS otimizado (last access + 8.3 desativados)" } else { "NTFS restaurado" }
}

function Invoke-DisableErrorReporting {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "sc" "config WerSvc start= disabled"
        Run-Hidden "sc" "stop WerSvc"
    } else {
        Run-Hidden "sc" "config WerSvc start= demand"
    }
    return if ($Enable) { "Error Reporting desativado" } else { "Error Reporting restaurado" }
}

function Invoke-DisableAutoMaintenance {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" "MaintenanceDisabled" $(if ($Enable) { 1 } else { 0 })
    return if ($Enable) { "Manutencao automatica desativada" } else { "Manutencao automatica restaurada" }
}

function Invoke-DisableEdgePreloading {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    # Edge Chromium (caminho correto para o Edge atual)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "StartupBoostEnabled" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "BackgroundModeEnabled" $val
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Edge" "StartupBoostEnabled" $val
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Edge" "BackgroundModeEnabled" $val
    return if ($Enable) { "Edge Preloading e background mode desativados" } else { "Edge Preloading restaurado" }
}

# =============== INTERNET ===============

function Invoke-DnsFlush {
    param([bool]$Enable)
    if (-not $Enable) { return "Cache DNS nao alterado." }
    Run-Hidden "ipconfig" "/flushdns"
    return "Cache DNS limpo com sucesso"
}

function Invoke-TcpOptimize {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "netsh" "int tcp set global autotuninglevel=normal"
        Run-Hidden "netsh" "int tcp set global chimney=disabled"
        Run-Hidden "netsh" "int tcp set global rss=enabled"
        Run-Hidden "netsh" "int tcp set global ecncapability=disabled"
        Run-Hidden "netsh" "int tcp set global timestamps=disabled"
    } else {
        Run-Hidden "netsh" "int tcp set global autotuninglevel=normal"
        Run-Hidden "netsh" "int tcp set global ecncapability=default"
    }
    return if ($Enable) { "TCP otimizado para baixa latencia" } else { "TCP restaurado ao padrao" }
}

function Invoke-PingReducer {
    param([bool]$Enable)
    if ($Enable) {
        # Normal autotuning + RSS ativado + ECN desativado = menor latencia
        Run-Hidden "netsh" "int tcp set global autotuninglevel=normal"
        Run-Hidden "netsh" "int tcp set global rss=enabled"
        Run-Hidden "netsh" "int tcp set global ecncapability=disabled"
        Run-Hidden "netsh" "int tcp set global timestamps=disabled"
        Run-Hidden "netsh" "int tcp set global initialrto=2000"
        # Remove reserva de banda QoS (20%)
        if ($script:IsAdmin) {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
        }
    } else {
        Run-Hidden "netsh" "int tcp set global autotuninglevel=normal"
        Run-Hidden "netsh" "int tcp set global ecncapability=default"
        Run-Hidden "netsh" "int tcp set global initialrto=3000"
        if ($script:IsAdmin) {
            Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "Rede Gaming Pro: TCP otimizado + QoS 0% + ECN off" } else { "Rede restaurada ao padrao" }
}

function Invoke-DisableNetworkThrottling {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $throttling = if ($Enable) { 4294967295 } else { 10 }
    $resp = if ($Enable) { 0 } else { 20 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" $throttling
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" $resp
    return if ($Enable) { "Network Throttling desativado" } else { "Network Throttling padrao restaurado" }
}

function Invoke-DisableDeliveryOptimization {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" $(if ($Enable) { 0 } else { 3 })
    return if ($Enable) { "Delivery Optimization desativado" } else { "Delivery Optimization restaurado" }
}

function Invoke-NetworkCleaner {
    param([bool]$Enable)
    if (-not $Enable) { return "Network Cleaner nao executado (ja estava desativado)." }
    Run-Hidden "ipconfig" "/flushdns"
    Run-Hidden "ipconfig" "/release"
    Run-Hidden "ipconfig" "/renew"
    Run-Hidden "netsh" "winsock reset"
    return "Network Cleaner executado (DNS + IP renovado + Winsock - requer reinicio)"
}

function Invoke-ResetWinsock {
    param([bool]$Enable)
    if (-not $Enable) { return "Winsock nao alterado." }
    Run-Hidden "netsh" "winsock reset"
    Run-Hidden "netsh" "int ip reset"
    return "Winsock e TCP/IP resetados (requer reinicio)"
}

function Invoke-DnsGaming {
    param([bool]$Enable)
    if ($Enable) {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112") -ErrorAction SilentlyContinue
        }
        return "DNS Gaming aplicado (Cloudflare + Quad9)"
    } else {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        return "DNS restaurado ao padrao (DHCP)"
    }
}

function Invoke-DisableNagles {
    param([bool]$Enable)
    $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -ErrorAction SilentlyContinue
    foreach ($iface in $interfaces) {
        if ($Enable) {
            Set-ItemProperty -Path $iface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $iface.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $iface.PSPath -Name "TcpDelAckTicks" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        } else {
            Remove-ItemProperty -Path $iface.PSPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $iface.PSPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $iface.PSPath -Name "TcpDelAckTicks" -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "Nagle's Algorithm desativado" } else { "Nagle's Algorithm restaurado" }
}

function Invoke-DisableLso {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "netsh" "int tcp set global chimney=disabled"
        Get-NetAdapterLso -ErrorAction SilentlyContinue | Disable-NetAdapterLso -ErrorAction SilentlyContinue
    } else {
        Get-NetAdapterLso -ErrorAction SilentlyContinue | Enable-NetAdapterLso -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "LSO desativado" } else { "LSO restaurado" }
}

function Invoke-DisableP2PUpdates {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 3 }
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" $val
    return if ($Enable) { "Updates P2P desativados" } else { "Updates P2P restaurados" }
}

# =============== GRAPHICS ===============

function Invoke-NvidiaOptimize {
    param([bool]$Enable)
    if ($Enable) {
        # Telemetria NVIDIA (scheduled tasks)
        @('NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}',
          'NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}',
          'NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}',
          'NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'
        ) | ForEach-Object { Run-Hidden "schtasks" "/change /tn `"$_`" /disable" }
        # DirectX: VRR + SwapEffect upgrade
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;" "String"
        # GPU max performance via power plan
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 1"
            Run-Hidden "powercfg" "/setactive scheme_current"
        }
        # Desativar NVIDIA overlay/share (reduz overhead)
        Set-RegistryValue "HKCU:\Software\NVIDIA Corporation\NvControlPanel2\Client" "OptInOrOutPreference" 0
        # Desativar container de telemetria NVIDIA
        if ($script:IsAdmin) {
            Run-Hidden "sc" "config NvTelemetryContainer start= disabled"
            Run-Hidden "sc" "stop NvTelemetryContainer"
        }
    } else {
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=0;" "String"
        Remove-ItemProperty "HKCU:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name "OptInOrOutPreference" -ErrorAction SilentlyContinue
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 0"
            Run-Hidden "powercfg" "/setactive scheme_current"
            Run-Hidden "sc" "config NvTelemetryContainer start= demand"
        }
    }
    return if ($Enable) { "NVIDIA: telemetria off + overlay off + GPU max perf" } else { "NVIDIA restaurada" }
}

function Invoke-AmdOptimize {
    param([bool]$Enable)
    if ($Enable) {
        # TDR delay: evita crash de driver em cargas pesadas
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "TdrDelay" 8
        # DirectX: VRR + SwapEffect upgrade
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;" "String"
        # GPU max performance via power plan
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 1"
            Run-Hidden "powercfg" "/setactive scheme_current"
        }
        # Hybrid graphics: forca GPU dedicada (laptops AMD+Intel)
        Run-Hidden "reg" 'add "HKCU\Software\AMD\CN" /v PowerXpressForceNGPCFlag /t REG_DWORD /d 1 /f'
    } else {
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -ErrorAction SilentlyContinue
        Set-RegistryValue "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" "DirectXUserGlobalSettings" "VRROptimizeEnable=0;" "String"
        Run-Hidden "reg" 'delete "HKCU\Software\AMD\CN" /v PowerXpressForceNGPCFlag /f'
        if ($script:IsAdmin) {
            Run-Hidden "powercfg" "/setacvalueindex scheme_current 4f971e89-eebd-4455-a8de-9e59040e7347 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c 0"
            Run-Hidden "powercfg" "/setactive scheme_current"
        }
    }
    return if ($Enable) { "AMD: TDR + GPU max perf + DirectX otimizados" } else { "AMD restaurada" }
}

function Invoke-EnableHags {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar HAGS." }
    $v = if ($Enable) { 2 } else { 1 }
    Run-Hidden "reg" "add `"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`" /v HwSchMode /t REG_DWORD /d $v /f"
    return if ($Enable) { "HAGS habilitado" } else { "HAGS desabilitado" }
}

function Invoke-ClearShaderCache {
    param([bool]$Enable)
    if (-not $Enable) { return "Cache de shaders nao alterado." }
    $removed = 0
    $dirs = @(
        "$env:LOCALAPPDATA\D3DSCache",
        "$env:LOCALAPPDATA\NVIDIA\DXCache",
        "$env:LOCALAPPDATA\NVIDIA\GLCache",
        "$env:LOCALAPPDATA\AMD\DxCache"
    )
    foreach ($d in $dirs) { $removed += Delete-FilesSafe $d }
    return "Cache de shaders limpo. Itens removidos: $removed"
}

function Invoke-DisableMpo {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" "OverlayTestMode" $(if ($Enable) { 5 } else { 0 })
    return if ($Enable) { "MPO desativado" } else { "MPO restaurado" }
}

# =============== KERNEL ===============

function Invoke-KernelDynamicTick {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar BCD." }
    if ($Enable) { Run-Hidden "bcdedit" "/set disabledynamictick yes" }
    else { Run-Hidden "bcdedit" "/deletevalue disabledynamictick" }
    return if ($Enable) { "Dynamic Tick desativado (requer reinicio)" } else { "Dynamic Tick restaurado (requer reinicio)" }
}

function Invoke-KernelPlatformClock {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar BCD." }
    if ($Enable) { Run-Hidden "bcdedit" "/deletevalue useplatformclock" }
    else { Run-Hidden "bcdedit" "/set useplatformclock yes" }
    return if ($Enable) { "useplatformclock desabilitado (TSC mais rapido)" } else { "useplatformclock forcado (HPET)" }
}

function Invoke-KernelTscSyncPolicy {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador para alterar BCD." }
    if ($Enable) { Run-Hidden "bcdedit" "/set tscsyncpolicy Enhanced" }
    else { Run-Hidden "bcdedit" "/deletevalue tscsyncpolicy" }
    return if ($Enable) { "TSCSyncPolicy=Enhanced aplicado (requer reinicio)" } else { "TSCSyncPolicy padrao restaurado" }
}

function Invoke-KernelWin32PrioritySeparation {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 38 } else { 2 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" $val
    return if ($Enable) { "Prioridade Win32 otimizada para foreground (38)" } else { "Prioridade Win32 restaurada (2)" }
}

function Invoke-DisableHpet {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "bcdedit" "/deletevalue useplatformclock"
        Run-Hidden "bcdedit" "/set useplatformtick yes"
    } else {
        Run-Hidden "bcdedit" "/deletevalue useplatformtick"
    }
    return if ($Enable) { "HPET desativado (requer reinicio)" } else { "HPET restaurado (requer reinicio)" }
}

function Invoke-DisableCStates {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor IDLEDISABLE 1"
        Run-Hidden "powercfg" "/setactive scheme_current"
    } else {
        Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor IDLEDISABLE 0"
        Run-Hidden "powercfg" "/setactive scheme_current"
    }
    return if ($Enable) { "C-States desabilitados" } else { "C-States restaurados" }
}

function Invoke-DisableMemoryCompression {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
    } else {
        Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Memory Compression desabilitada" } else { "Memory Compression restaurada" }
}

function Invoke-OptimizeIoPriority {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        # SFIO priority alta para Games
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "SFIO Priority" "High" "String"
        # Clock Rate: 10000 = 1ms (reduz latencia de agendamento)
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Clock Rate" 10000
        # Affinity: 0 = usa todos os nucleos para Games
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Affinity" 0
        # IRQ boost para dispositivos de entrada (mouse/teclado)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" "IRQ8Priority" 1
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" "IRQ16Priority" 1
    } else {
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "SFIO Priority" "Normal" "String"
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ16Priority" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "I/O Priority: SFIO High + Clock Rate 1ms + IRQ boost" } else { "I/O Priority restaurada" }
}

function Invoke-MemoryManagerPro {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        # Desativar prefetcher (SSD: nao precisa, reduz I/O)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0
        # Heap decommit threshold: reduz fragmentacao de heap (0x040000 = 256KB)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "HeapDeCommitFreeBlockThreshold" 0x040000
        # Nao limpar pagefile ao desligar (shutdown mais rapido)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0
        # SecondLevelDataCache: reportar tamanho L2 para o scheduler (melhora scheduling)
        $l2 = (Get-CimInstance -ClassName Win32_CacheMemory -ErrorAction SilentlyContinue | Where-Object { $_.Level -eq 3 } | Select-Object -First 1).MaxCacheSize
        if ($l2) { Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "SecondLevelDataCache" $l2 }
    } else {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 3
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "HeapDeCommitFreeBlockThreshold" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SecondLevelDataCache" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Memory Manager Pro: prefetch off + heap otimizado" } else { "Memory Manager Pro revertido" }
}

function Invoke-CacheManagerPro {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        # MFT zone reservation: 2 = 25% (reduz fragmentacao do MFT)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMftZoneReservation" 2
        # NTFS memory usage: 2 = usa mais cache
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMemoryUsage" 2
        # I/O page lock limit: 512 KB (melhora throughput de I/O)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "IoPageLockLimit" 524288
        # Disable pagefile at shutdown (nao limpa paginacao ao desligar = boot mais rapido)
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0
    } else {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMftZoneReservation" 1
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMemoryUsage" 1
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -ErrorAction SilentlyContinue
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0
    }
    return if ($Enable) { "Cache Manager Pro: NTFS MFT + I/O page lock otimizados" } else { "Cache Manager Pro revertido" }
}

function Invoke-DisablePagingExecutive {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" $val
    return if ($Enable) { "Paging Executive desabilitado (requer 16GB+ RAM, REINICIE!)" } else { "Paging Executive restaurado" }
}

function Invoke-OptimizeNtfsMemory {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMemoryUsage" 2
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsDisableLastAccessUpdate" 1
    } else {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsMemoryUsage" 1
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsDisableLastAccessUpdate" 0
    }
    return if ($Enable) { "NTFS Memory otimizado (256MB cache)" } else { "NTFS Memory restaurado" }
}

# =============== INPUT LAG ===============

function Invoke-MouseOptimize {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseSensitivity /t REG_SZ /d 10 /f'
    } else {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 6 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 10 /f'
    }
    return if ($Enable) { "Mouse otimizado (aceleracao desativada, 6/11)" } else { "Mouse restaurado" }
}

function Invoke-KeyboardBoost {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f'
    } else {
        Run-Hidden "reg" 'add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 1 /f'
        Run-Hidden "reg" 'add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 20 /f'
    }
    return if ($Enable) { "Teclado otimizado (delay 0, speed max)" } else { "Teclado restaurado" }
}

function Invoke-DisableMouseTrails {
    param([bool]$Enable)
    $val = if ($Enable) { "0" } else { "-1" }
    Run-Hidden "reg" "add `"HKCU\Control Panel\Mouse`" /v MouseTrails /t REG_SZ /d $val /f"
    return if ($Enable) { "Trilha do mouse desativada" } else { "Trilha do mouse restaurada" }
}

function Invoke-OptimizeUsbPower {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\USB" "DisableSelectiveSuspend" $(if ($Enable) { 1 } else { 0 })
    # Desativar suspend em todos os hubs USB
    Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | ForEach-Object {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.InstanceId)\Device Parameters"
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "SelectiveSuspendEnabled" -Value $val -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "USB Power Saving desativado" } else { "USB Power Saving restaurado" }
}

function Invoke-DisableFocusAssist {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    # Sons de notificacao
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" $val
    # Toasts habilitados (0 = desativa todos os popups)
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" $val
    # Badge de notificacao
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_BADGING_ENABLED" $val
    # Focus Assist: desativa quiet hours automatico durante jogos
    $qaVal = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" $qaVal
    return if ($Enable) { "Notificacoes desativadas (sons + toasts + badges)" } else { "Notificacoes restauradas" }
}

function Invoke-OptimizePcieAspm {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Run-Hidden "powercfg" "/setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 ee12f906-d277-404b-b6da-e5fa1a576df5 0"
    } else {
        Run-Hidden "powercfg" "/setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 ee12f906-d277-404b-b6da-e5fa1a576df5 2"
    }
    Run-Hidden "powercfg" "/setactive scheme_current"
    return if ($Enable) { "PCIe ASPM desabilitado" } else { "PCIe ASPM restaurado" }
}

function Invoke-OptimizeAudioLatency {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Latency Sensitive" "True" "String"
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Priority" 1
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Scheduling Category" "High" "String"
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "SFIO Priority" "High" "String"
    } else {
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Latency Sensitive" "False" "String"
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Priority" 6
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "Scheduling Category" "Medium" "String"
        Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" "SFIO Priority" "Normal" "String"
    }
    return if ($Enable) { "Audio Latency otimizado (Pro Audio priority alta)" } else { "Audio Latency padrao" }
}

# =============== MENU ===============

function Invoke-DisableAutoplay {
    param([bool]$Enable)
    $val = if ($Enable) { 255 } else { 145 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" $val
    return if ($Enable) { "AutoPlay desativado" } else { "AutoPlay restaurado" }
}

function Invoke-DisableSoftLanding {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" $val
    return if ($Enable) { "Dicas do Windows desativadas" } else { "Dicas do Windows restauradas" }
}

# =============== NOVAS OTIMIZACOES (SISTEMA) ===============

function Invoke-DisableWindowsSpotlight {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-310093Enabled" $val
    return if ($Enable) { "Windows Spotlight desativado" } else { "Windows Spotlight restaurado" }
}

function Invoke-DisableSearchWeb {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" $val
    if ($script:IsAdmin) {
        $pVal = if ($Enable) { 1 } else { 0 }
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" $pVal
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" $val
    }
    return if ($Enable) { "Busca web no Iniciar desativada" } else { "Busca web restaurada" }
}

function Invoke-DisableNotificationCenter {
    param([bool]$Enable)
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" $val
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" $(if ($Enable) { 0 } else { 1 })
    return if ($Enable) { "Centro de notificacoes desativado" } else { "Centro de notificacoes restaurado" }
}

# =============== NOVAS OTIMIZACOES (GAMEBOOST) ===============

function Invoke-Cs2Boost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-DisableXboxGameBar $Enable
    Invoke-FullscreenOptimization $Enable
    Invoke-DisableNetworkThrottling $Enable
    Invoke-OptimizeGamesSystemProfile $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csgo.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    } elseif (-not $Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /f' 2>$null
        Run-Hidden "reg" 'delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csgo.exe\PerfOptions" /f' 2>$null
    }
    return if ($Enable) { "CS2/CS:GO Boost COMPLETO aplicado" } else { "CS2/CS:GO Boost revertido" }
}

function Invoke-ApexBoost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-DisableXboxGameBar $Enable
    Invoke-FullscreenOptimization $Enable
    Invoke-DisableNetworkThrottling $Enable
    Invoke-OptimizeGamesSystemProfile $Enable
    Invoke-UltimatePerformance $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\r5apex.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    } elseif (-not $Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\r5apex.exe\PerfOptions" /f' 2>$null
    }
    return if ($Enable) { "Apex Legends Boost COMPLETO aplicado" } else { "Apex Legends Boost revertido" }
}

function Invoke-LolBoost {
    param([bool]$Enable)
    Invoke-DisableGameDvr $Enable
    Invoke-DisableXboxGameBar $Enable
    Invoke-DisableNetworkThrottling $Enable
    Invoke-DisableNagles $Enable
    if ($Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\League of Legends.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 3 /f'
    } elseif (-not $Enable -and $script:IsAdmin) {
        Run-Hidden "reg" 'delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\League of Legends.exe\PerfOptions" /f' 2>$null
    }
    return if ($Enable) { "League of Legends Boost aplicado" } else { "LoL Boost revertido" }
}

# =============== NOVAS OTIMIZACOES (INTERNET) ===============

function Invoke-DisableBandwidthLimit {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
    } else {
        Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Limite de banda QoS removido (0%)" } else { "Limite de banda QoS padrao" }
}

function Invoke-OptimizeIRPStack {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $val = if ($Enable) { 32 } else { 15 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "IRPStackSize" $val
    return if ($Enable) { "IRPStackSize aumentado para 32 (melhor throughput)" } else { "IRPStackSize padrao restaurado" }
}

# =============== NOVAS OTIMIZACOES (BOOSTER) ===============

function Invoke-DisableOneDriveStartup {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "reg" 'delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /f' 2>$null
        if ($script:IsAdmin) {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
        }
    } else {
        if ($script:IsAdmin) {
            Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "OneDrive desativado na inicializacao" } else { "OneDrive restaurado" }
}

function Invoke-OptimizeSvcHostSplit {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum
        $threshold = if ($ram) { [int]($ram / 1KB) } else { 16777216 }
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" $threshold
    } else {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" 3670016
    }
    return if ($Enable) { "SvcHost Split otimizado (menos processos svchost)" } else { "SvcHost Split padrao" }
}

# =============== NOVAS OTIMIZACOES (INPUT LAG) ===============

function Invoke-OptimizeTimerResolution {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "GlobalTimerResolutionRequests" 1
    } else {
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Timer Resolution otimizado (alta precisao)" } else { "Timer Resolution padrao" }
}

# =============== NOVAS OTIMIZACOES ADICIONADAS ===============

function Invoke-DisableEdgeTelemetry {
    param([bool]$Enable)
    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        "HKCU:\Software\Policies\Microsoft\Edge"
    )
    foreach ($p in $paths) {
        if ($Enable) {
            Set-RegistryValue $p "MetricsReportingEnabled" 0
            Set-RegistryValue $p "SendSiteInfoToImproveServices" 0
            Set-RegistryValue $p "PersonalizationReportingEnabled" 0
            Set-RegistryValue $p "DiagnosticData" 0
        } else {
            Remove-ItemProperty $p -Name "MetricsReportingEnabled" -ErrorAction SilentlyContinue
            Remove-ItemProperty $p -Name "SendSiteInfoToImproveServices" -ErrorAction SilentlyContinue
            Remove-ItemProperty $p -Name "PersonalizationReportingEnabled" -ErrorAction SilentlyContinue
            Remove-ItemProperty $p -Name "DiagnosticData" -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "Telemetria do Edge desativada" } else { "Telemetria do Edge restaurada" }
}

function Invoke-ReducedProcesses {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    # Services to disable (keeping all Xbox services intact)
    $svcs = @("WerSvc","DiagTrack","dmwappushservice","MapsBroker","lfsvc","SharedAccess","TrkWks","WbioSrvc","WMPNetworkSvc","icssvc","WSearch")
    foreach ($s in $svcs) {
        $obj = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($obj) {
            Set-PopupStep "$( if($Enable){ 'Parando' } else { 'Restaurando' } ): $s"
            try {
                if ($Enable) {
                    if ($obj.Status -ne 'Stopped') { $obj.Stop(); $obj.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(4)) }
                    Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                } else {
                    Set-Service -Name $s -StartupType Manual -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    return if ($Enable) { "Processos reduzidos (Xbox preservado)" } else { "Servicos restaurados" }
}

function Invoke-LaptopPowerTweaks {
    param([bool]$Enable)
    if ($Enable) {
        Set-PopupStep "Configurando bateria: balanceado-agressivo"
        Run-Hidden "powercfg" "/setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 100"
        Run-Hidden "powercfg" "/setdcvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 75"
        Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100"
        Run-Hidden "powercfg" "/setactive scheme_current"
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" "Attributes" 2
    } else {
        Run-Hidden "powercfg" "/restoredefaultschemes"
    }
    return if ($Enable) { "Energia para notebook otimizada (AC/DC)" } else { "Planos de energia restaurados" }
}

function Invoke-DisablePsModuleLogging {
    param([bool]$Enable)
    if ($Enable) {
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    } else {
        Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Telemetria do PowerShell desativada" } else { "Logs do PowerShell restaurados" }
}

function Invoke-ChangeDefaultTerminal {
    param([bool]$Enable)
    if ($Enable) {
        # Set Windows Terminal as default (GUID for Windows Terminal)
        Set-RegistryValue "HKCU:\Console\%%Startup" "DelegationConsole" "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}" "String"
        Set-RegistryValue "HKCU:\Console\%%Startup" "DelegationTerminal" "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}" "String"
    } else {
        Remove-ItemProperty "HKCU:\Console\%%Startup" -Name "DelegationConsole" -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKCU:\Console\%%Startup" -Name "DelegationTerminal" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Windows Terminal definido como terminal padrao" } else { "Terminal padrao restaurado" }
}

function Invoke-OptimizeDriveForGaming {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-PopupStep "Desativando last access timestamp (NTFS)"
        Run-Hidden "fsutil" "behavior set disablelastaccess 1"
        Set-PopupStep "Desativando 8.3 filename generation"
        Run-Hidden "fsutil" "behavior set disable8dot3 1"
        Set-PopupStep "Configurando I/O scheduler"
        # Disable SuperFetch / SysMain for SSD
        $obj = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
        if ($obj) {
            $obj.Stop()
            Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
        }
        # Write cache enabled
        $disks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
        foreach ($disk in $disks) {
            $diskIndex = $disk.Index
            Run-Hidden "powershell" "-Command \"Get-PhysicalDisk | Where-Object DeviceId -eq '$diskIndex' | Set-PhysicalDisk -MediaType SSD -ErrorAction SilentlyContinue\""
        }
    } else {
        Run-Hidden "fsutil" "behavior set disablelastaccess 0"
        Run-Hidden "fsutil" "behavior set disable8dot3 0"
        $obj = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
        if ($obj) { Set-Service -Name "SysMain" -StartupType Automatic -ErrorAction SilentlyContinue }
    }
    return if ($Enable) { "SSD/HD otimizado para jogos" } else { "Configuracoes de disco restauradas" }
}

function Invoke-DisableHomegroup {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    $svcs = @("HomeGroupListener", "HomeGroupProvider")
    foreach ($s in $svcs) {
        $obj = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($obj) {
            try {
                if ($Enable) {
                    if ($obj.Status -ne 'Stopped') { $obj.Stop(); $obj.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(4)) }
                    Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                } else {
                    Set-Service -Name $s -StartupType Manual -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    return if ($Enable) { "Homegroup desativado" } else { "Homegroup restaurado" }
}

function Invoke-DisableHibernation {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    Set-PopupStep $(if ($Enable) { "Desativando hibernacao (powercfg /h off)" } else { "Ativando hibernacao" })
    if ($Enable) {
        Run-Hidden "powercfg" "/h off"
    } else {
        Run-Hidden "powercfg" "/h on"
    }
    return if ($Enable) { "Hibernacao desativada (libera hiberfil.sys)" } else { "Hibernacao ativada" }
}

function Invoke-DisableGameDvrFull {
    param([bool]$Enable)
    $dvrVal  = if ($Enable) { 0 } else { 1 }
    $fseVal  = if ($Enable) { 2 } else { 0 }  # 2 = desativa FSO/fullscreen opts
    $honVal  = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_Enabled" $dvrVal
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_FSEBehaviorMode" $fseVal
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_HonorUserFSEBehaviorMode" $honVal
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_DXGIHonorFSEWindowsCompatible" $honVal
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" $dvrVal
    return if ($Enable) { "DVR + FSO completamente desativados" } else { "DVR + FSO restaurados" }
}

function Invoke-DisableIpv6 {
    param([bool]$Enable)
    $val = if ($Enable) { 255 } else { 0 }
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" $val
    if ($Enable) {
        Run-Hidden "netsh" "interface ipv6 set global randomizeidentifiers=disabled"
        Run-Hidden "netsh" "interface ipv6 set privacy state=disabled"
    } else {
        Run-Hidden "netsh" "interface ipv6 set global randomizeidentifiers=enabled"
        Run-Hidden "netsh" "interface ipv6 set privacy state=enabled"
    }
    return if ($Enable) { "IPv6 desativado" } else { "IPv6 restaurado" }
}

function Invoke-DisableTeredo {
    param([bool]$Enable)
    if ($Enable) {
        Run-Hidden "netsh" "interface teredo set state disabled"
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 8
    } else {
        Run-Hidden "netsh" "interface teredo set state default"
    }
    return if ($Enable) { "Teredo desativado" } else { "Teredo restaurado" }
}

function Invoke-DisableBackgroundAppsAll {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" $(if ($Enable) { 2 } else { 0 })
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Value $val -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Value $val -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Apps em segundo plano bloqueados" } else { "Apps em segundo plano liberados" }
}

function Invoke-DisableFso {
    param([bool]$Enable)
    $fseVal = if ($Enable) { 2 } else { 0 }  # 2 = desativa Fullscreen Optimizations
    $honVal = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_FSEBehaviorMode" $fseVal
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_HonorUserFSEBehaviorMode" $honVal
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_DXGIHonorFSEWindowsCompatible" $honVal
    $dxVal = if ($Enable) { "SwapEffectUpgradeEnable=0;" } else { "SwapEffectUpgradeEnable=1;" }
    Run-Hidden "reg" "add \"HKCU\Software\Microsoft\DirectX\UserGpuPreferences\" /v DirectXUserGlobalSettings /t REG_SZ /d \"$dxVal\" /f"
    return if ($Enable) { "FSO (Fullscreen Optimizations) desativado" } else { "FSO restaurado" }
}

function Invoke-DisableCopilot {
    param([bool]$Enable)
    $val = if ($Enable) { 0 } else { 1 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCopilotButton" $val
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" $(if ($Enable) { 1 } else { 0 })
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\WindowsCopilot" "Enabled" $val
    return if ($Enable) { "Microsoft Copilot desativado" } else { "Copilot restaurado" }
}

function Invoke-DisableTrayNotifications {
    param([bool]$Enable)
    $val = if ($Enable) { 1 } else { 0 }
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" $(if ($Enable) { 0 } else { 1 })
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" $(if ($Enable) { 0 } else { 1 })
    Run-Hidden "reg" "add \"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\" /v PeopleBand /t REG_DWORD /d $val /f"
    # Calendar/clock notifications
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" "UseActionCenterExperience" $(if ($Enable) { 0 } else { 1 })
    return if ($Enable) { "Notificacoes da bandeja e calendario desativadas" } else { "Notificacoes restauradas" }
}

function Invoke-GamingConfigPro {
    param([bool]$Enable)
    Set-PopupStep "Aplicando MMCSS Gaming..."
    Invoke-OptimizeMmcss $Enable
    Set-PopupStep "GPU Thread Priority..."
    Invoke-OptimizeGpuThreadPriority $Enable
    Set-PopupStep "Game Mode..."
    Invoke-GameMode $Enable
    Set-PopupStep "Desativando Game DVR..."
    Invoke-DisableGameDvrFull $Enable
    Set-PopupStep "Otimizando NTFS..."
    if ($script:IsAdmin) {
        Run-Hidden "fsutil" "behavior set disablelastaccess 1"
        Run-Hidden "fsutil" "behavior set disable8dot3 1"
    }
    Set-PopupStep "Priority Win32: foreground"
    Invoke-KernelWin32PrioritySeparation $Enable
    Set-PopupStep "Desativando Network Throttling..."
    Invoke-DisableNetworkThrottling $Enable
    return if ($Enable) { "Config de jogos PRO aplicada (7 tweaks)" } else { "Config de jogos PRO revertida" }
}

function Invoke-OptimizeContextMenu {
    param([bool]$Enable)
    if ($Enable) {
        # Remove shadow from context menu for snappier response
        Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" 0
        Set-RegistryValue "HKCU:\Control Panel\Desktop" "MenuShowDelay" "50" "String"
        # Disable context menu animations
        Run-Hidden "reg" "add \"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /v DesktopLivePreviewHoverTime /t REG_DWORD /d 1 /f"
        # Use old right-click menu on Windows 11
        Set-RegistryValue "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "" "" "String"
    } else {
        Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" 1
        Set-RegistryValue "HKCU:\Control Panel\Desktop" "MenuShowDelay" "400" "String"
        Remove-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Menu de contexto otimizado (menu classico + rapido)" } else { "Menu de contexto restaurado" }
}

function Invoke-OptimizeIntelCpu {
    param([bool]$Enable)
    if (-not $script:IsAdmin) { return "Requer administrador." }
    if ($Enable) {
        Set-PopupStep "Intel: desativando throttling de energia"
        Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100"
        Run-Hidden "powercfg" "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100"
        Set-PopupStep "Intel: Speed Shift priority"
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" "Attributes" 2
        Run-Hidden "powercfg" "/setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 100"
        Set-PopupStep "Intel: desativando C-States via registro"
        Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Processor" "Capabilities" 0x0007e066
        Run-Hidden "powercfg" "/setactive scheme_current"
        Set-PopupStep "Intel: prioridade de foreground"
        Invoke-KernelWin32PrioritySeparation $Enable
    } else {
        Run-Hidden "powercfg" "/restoredefaultschemes"
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Processor" -Name "Capabilities" -ErrorAction SilentlyContinue
        Invoke-KernelWin32PrioritySeparation $false
    }
    return if ($Enable) { "CPU Intel otimizada para max performance" } else { "CPU Intel restaurada" }
}

function Invoke-DisableAdobeInetErrors {
    param([bool]$Enable)
    $adobeHosts = @(
        "0.0.0.0 activate.adobe.com"
        "0.0.0.0 practivate.adobe.com"
        "0.0.0.0 ereg.adobe.com"
        "0.0.0.0 activate.wip3.adobe.com"
        "0.0.0.0 wip3.adobe.com"
        "0.0.0.0 3dns-3.adobe.com"
        "0.0.0.0 adobeereg.com"
        "0.0.0.0 wwis-dubc1-vip60.adobe.com"
        "0.0.0.0 activate-sea.adobe.com"
    )
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if ($Enable) {
        Set-PopupStep "Bloqueando dominios Adobe no hosts"
        $current = Get-Content $hostsPath -ErrorAction SilentlyContinue
        foreach ($entry in $adobeHosts) {
            if ($current -notcontains $entry) {
                Add-Content $hostsPath "`n$entry" -ErrorAction SilentlyContinue
            }
        }
    } else {
        Set-PopupStep "Removendo entradas Adobe do hosts"
        $current = Get-Content $hostsPath -ErrorAction SilentlyContinue
        if ($current) {
            $cleaned = $current | Where-Object { $adobeHosts -notcontains $_ }
            Set-Content $hostsPath $cleaned -ErrorAction SilentlyContinue
        }
    }
    return if ($Enable) { "Erros de internet Adobe bloqueados" } else { "Entradas Adobe removidas do hosts" }
}

function Invoke-OptimizeAdobe {
    param([bool]$Enable)
    if ($Enable) {
        Set-PopupStep "Desativando atualizacoes automaticas Adobe"
        $svc = Get-Service -Name "AdobeUpdateService" -ErrorAction SilentlyContinue
        if ($svc) { $svc.Stop(); Set-Service -Name "AdobeUpdateService" -StartupType Disabled -ErrorAction SilentlyContinue }
        $svc2 = Get-Service -Name "AdobeARMservice" -ErrorAction SilentlyContinue
        if ($svc2) { $svc2.Stop(); Set-Service -Name "AdobeARMservice" -StartupType Disabled -ErrorAction SilentlyContinue }
        Set-PopupStep "Desativando telemetria Adobe"
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" "bUpdater" 0
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" "bUpdater" 0
        Set-RegistryValue "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\FeatureLockDown" "bUpdater" 0
    } else {
        $svc = Get-Service -Name "AdobeARMservice" -ErrorAction SilentlyContinue
        if ($svc) { Set-Service -Name "AdobeARMservice" -StartupType Automatic -ErrorAction SilentlyContinue }
        Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -ErrorAction SilentlyContinue
    }
    return if ($Enable) { "Adobe otimizado (atualizacoes e telemetria off)" } else { "Adobe restaurado" }
}

# ==================== MAPEAMENTO OTIMIZACOES ====================

$script:OptimizationMap = @{
    # Sistema
    "clean_temp"                    = { param($e) Invoke-CleanTemp $e }
    "optimize_services"             = { param($e) Invoke-OptimizeServices $e }
    "defrag_disk"                   = { param($e) Invoke-DefragDisk $e }
    "clean_registry"                = { param($e) Invoke-CleanRegistry $e }
    "disable_animations"            = { param($e) Invoke-DisableAnimations $e }
    "power_plan"                    = { param($e) Invoke-SetMaxPowerPlan $e }
    "prefetch_superfetch"           = { param($e) Invoke-PrefetchSuperfetch $e }
    "disable_telemetry"             = { param($e) Invoke-DisableTelemetry $e }
    "disable_transparency"          = { param($e) Invoke-DisableTransparency $e }
    "ultimate_performance"          = { param($e) Invoke-UltimatePerformance $e }
    "disable_consumer_features"     = { param($e) Invoke-DisableConsumerFeatures $e }
    "disable_cortana"               = { param($e) Invoke-DisableCortana $e }
    "disable_feedback"              = { param($e) Invoke-DisableFeedback $e }
    "menu_delay_fast"               = { param($e) Invoke-MenuDelayFast $e }
    "disable_sticky_keys"           = { param($e) Invoke-DisableStickyKeys $e }
    "disable_background_apps"       = { param($e) Invoke-DisableBackgroundApps $e }
    "startup_delay_zero"            = { param($e) Invoke-StartupDelayZero $e }
    "taskbar_news_off"              = { param($e) Invoke-TaskbarNewsOff $e }
    "disable_compat_assistant"      = { param($e) Invoke-DisableCompatAssistant $e }
    "disable_chrome_telemetry"      = { param($e) Invoke-DisableChromeTelemetry $e }
    "disable_nvidia_telemetry"      = { param($e) Invoke-DisableNvidiaTelemetry $e }
    "disable_office_telemetry"      = { param($e) Invoke-DisableOfficeTelemetry $e }
    "disable_firefox_telemetry"     = { param($e) Invoke-DisableFirefoxTelemetry $e }
    "disable_wifi_sense"            = { param($e) Invoke-DisableWifiSense $e }
    "disable_system_restore"        = { param($e) Invoke-DisableSystemRestore $e }
    "disable_performance_throttle"  = { param($e) Invoke-DisablePerformanceThrottle $e }
    "disable_spectre_patch"         = { param($e) Invoke-DisableSpectrePatch $e }
    "disable_remote_assistance"     = { param($e) Invoke-DisableRemoteAssistance $e }
    "disable_windows_tips"          = { param($e) Invoke-DisableWindowsTips $e }
    "disable_location_services"     = { param($e) Invoke-DisableLocationServices $e }
    "disable_activity_history"      = { param($e) Invoke-DisableActivityHistory $e }
    "disable_clipboard_history"     = { param($e) Invoke-DisableClipboardHistory $e }
    "disable_advertising_id"        = { param($e) Invoke-DisableAdvertisingId $e }
    "disable_driver_updates"        = { param($e) Invoke-DisableDriverUpdates $e }
    # Games
    "game_mode"                     = { param($e) Invoke-GameMode $e }
    "fps_boost"                     = { param($e) Invoke-FpsBoost $e }
    "fullscreen_opt"                = { param($e) Invoke-FullscreenOptimization $e }
    "disable_game_dvr"              = { param($e) Invoke-DisableGameDvr $e }
    "disable_game_bar"              = { param($e) Invoke-DisableXboxGameBar $e }
    "disable_xbox_services"         = { param($e) Invoke-DisableXboxServices $e }
    "optimize_games_systemprofile"  = { param($e) Invoke-OptimizeGamesSystemProfile $e }
    "ultra_gaming_mode"             = { param($e) Invoke-UltraGamingMode $e }
    "master_gaming_optimization"    = { param($e) Invoke-MasterGamingOptimization $e }
    "optimize_mmcss"                = { param($e) Invoke-OptimizeMmcss $e }
    "optimize_gpu_thread_priority"  = { param($e) Invoke-OptimizeGpuThreadPriority $e }
    "disable_defender_realtime"     = { param($e) Invoke-DisableDefenderRealtime $e }
    # GameBoost
    "valorant_boost"                = { param($e) Invoke-ValorantBoost $e }
    "fortnite_boost"                = { param($e) Invoke-FortniteBoost $e }
    "fivem_boost"                   = { param($e) Invoke-FiveMBoost $e }
    "minecraft_boost"               = { param($e) Invoke-MinecraftBoost $e }
    "roblox_boost"                  = { param($e) Invoke-RobloxBoost $e }
    # Booster
    "cpu_boost"                     = { param($e) Invoke-CpuBoost $e }
    "ram_cleaner"                   = { param($e) Invoke-RamCleaner $e }
    "gpu_optimize"                  = { param($e) Invoke-GpuOptimize $e }
    "disable_search_index"          = { param($e) Invoke-DisableSearchIndex $e }
    "disable_print_spooler"         = { param($e) Invoke-DisablePrintSpooler $e }
    "remove_apps"                   = { param($e) Invoke-RemoveApps $e }
    "clean_browser_cache"           = { param($e) Invoke-CleanBrowserCache $e }
    "clean_prefetch"                = { param($e) Invoke-CleanPrefetch $e }
    "deep_clean"                    = { param($e) Invoke-DeepClean $e }
    "remove_old_drivers"            = { param($e) Invoke-RemoveOldDrivers $e }
    "disable_hibernation"           = { param($e) Invoke-DisableHibernation $e }
    "disable_fast_startup"          = { param($e) Invoke-DisableFastStartup $e }
    "optimize_ntfs"                 = { param($e) Invoke-OptimizeNtfs $e }
    "disable_error_reporting"       = { param($e) Invoke-DisableErrorReporting $e }
    "disable_auto_maintenance"      = { param($e) Invoke-DisableAutoMaintenance $e }
    "disable_edge_preloading"       = { param($e) Invoke-DisableEdgePreloading $e }
    # Internet
    "dns_flush"                     = { param($e) Invoke-DnsFlush $e }
    "tcp_optimize"                  = { param($e) Invoke-TcpOptimize $e }
    "ping_reducer"                  = { param($e) Invoke-PingReducer $e }
    "disable_network_throttling"    = { param($e) Invoke-DisableNetworkThrottling $e }
    "disable_delivery_optimization" = { param($e) Invoke-DisableDeliveryOptimization $e }
    "network_cleaner"               = { param($e) Invoke-NetworkCleaner $e }
    "reset_winsock"                 = { param($e) Invoke-ResetWinsock $e }
    "dns_gaming"                    = { param($e) Invoke-DnsGaming $e }
    "disable_nagles"                = { param($e) Invoke-DisableNagles $e }
    "disable_lso"                   = { param($e) Invoke-DisableLso $e }
    "disable_p2p_updates"           = { param($e) Invoke-DisableP2PUpdates $e }
    # Graphics
    "nvidia_opt"                    = { param($e) Invoke-NvidiaOptimize $e }
    "amd_opt"                       = { param($e) Invoke-AmdOptimize $e }
    "enable_hags"                   = { param($e) Invoke-EnableHags $e }
    "clear_shader_cache"            = { param($e) Invoke-ClearShaderCache $e }
    "disable_mpo"                   = { param($e) Invoke-DisableMpo $e }
    # Kernel
    "kernel_dynamic_tick"           = { param($e) Invoke-KernelDynamicTick $e }
    "kernel_platform_clock"         = { param($e) Invoke-KernelPlatformClock $e }
    "kernel_tsc_sync"               = { param($e) Invoke-KernelTscSyncPolicy $e }
    "kernel_priority_foreground"    = { param($e) Invoke-KernelWin32PrioritySeparation $e }
    "disable_hpet"                  = { param($e) Invoke-DisableHpet $e }
    "disable_c_states"              = { param($e) Invoke-DisableCStates $e }
    "disable_memory_compression"    = { param($e) Invoke-DisableMemoryCompression $e }
    "optimize_io_priority"          = { param($e) Invoke-OptimizeIoPriority $e }
    "memory_manager_pro"            = { param($e) Invoke-MemoryManagerPro $e }
    "cache_manager_pro"             = { param($e) Invoke-CacheManagerPro $e }
    "disable_paging_executive"      = { param($e) Invoke-DisablePagingExecutive $e }
    "optimize_ntfs_memory"          = { param($e) Invoke-OptimizeNtfsMemory $e }
    # Input Lag
    "mouse_optimize"                = { param($e) Invoke-MouseOptimize $e }
    "keyboard_boost"                = { param($e) Invoke-KeyboardBoost $e }
    "disable_mouse_trails"          = { param($e) Invoke-DisableMouseTrails $e }
    "optimize_usb_power"            = { param($e) Invoke-OptimizeUsbPower $e }
    "disable_focus_assist"          = { param($e) Invoke-DisableFocusAssist $e }
    "optimize_pcie_aspm"            = { param($e) Invoke-OptimizePcieAspm $e }
    "optimize_audio_latency"        = { param($e) Invoke-OptimizeAudioLatency $e }
    # Menu
    "disable_autoplay"              = { param($e) Invoke-DisableAutoplay $e }
    "disable_soft_landing"          = { param($e) Invoke-DisableSoftLanding $e }
    # Novas Otimizacoes
    "disable_windows_spotlight"     = { param($e) Invoke-DisableWindowsSpotlight $e }
    "disable_search_web"            = { param($e) Invoke-DisableSearchWeb $e }
    "disable_notification_center"   = { param($e) Invoke-DisableNotificationCenter $e }
    "cs2_boost"                     = { param($e) Invoke-Cs2Boost $e }
    "apex_boost"                    = { param($e) Invoke-ApexBoost $e }
    "lol_boost"                     = { param($e) Invoke-LolBoost $e }
    "disable_bandwidth_limit"       = { param($e) Invoke-DisableBandwidthLimit $e }
    "optimize_irp_stack"            = { param($e) Invoke-OptimizeIRPStack $e }
    "disable_onedrive_startup"      = { param($e) Invoke-DisableOneDriveStartup $e }
    "optimize_svchost_split"        = { param($e) Invoke-OptimizeSvcHostSplit $e }
    "optimize_timer_resolution"     = { param($e) Invoke-OptimizeTimerResolution $e }
    # 2026 novas
    "disable_edge_telemetry"        = { param($e) Invoke-DisableEdgeTelemetry $e }
    "reduced_processes"             = { param($e) Invoke-ReducedProcesses $e }
    "laptop_power_tweaks"           = { param($e) Invoke-LaptopPowerTweaks $e }
    "disable_ps_telemetry"          = { param($e) Invoke-DisablePsModuleLogging $e }
    "change_default_terminal"       = { param($e) Invoke-ChangeDefaultTerminal $e }
    "optimize_drive_gaming"         = { param($e) Invoke-OptimizeDriveForGaming $e }
    "disable_homegroup"             = { param($e) Invoke-DisableHomegroup $e }
    "disable_hibernation_full"      = { param($e) Invoke-DisableHibernation $e }
    "disable_dvr_full"              = { param($e) Invoke-DisableGameDvrFull $e }
    "disable_ipv6"                  = { param($e) Invoke-DisableIpv6 $e }
    "disable_teredo"                = { param($e) Invoke-DisableTeredo $e }
    "disable_bg_apps_all"           = { param($e) Invoke-DisableBackgroundAppsAll $e }
    "disable_fso"                   = { param($e) Invoke-DisableFso $e }
    "disable_copilot"               = { param($e) Invoke-DisableCopilot $e }
    "disable_tray_notifications"    = { param($e) Invoke-DisableTrayNotifications $e }
    "gaming_config_pro"             = { param($e) Invoke-GamingConfigPro $e }
    "optimize_context_menu"         = { param($e) Invoke-OptimizeContextMenu $e }
    "optimize_intel_cpu"            = { param($e) Invoke-OptimizeIntelCpu $e }
    "disable_adobe_inet"            = { param($e) Invoke-DisableAdobeInetErrors $e }
    "optimize_adobe"                = { param($e) Invoke-OptimizeAdobe $e }
}

# ==================== DEFINICAO DAS CATEGORIAS ====================

$script:Categories = [ordered]@{
    "Sistema" = @(
        @{ Key="clean_temp";                    Title="Limpar arquivos temporarios";        Desc="Remove .tmp, %temp% e cache do sistema" }
        @{ Key="optimize_services";             Title="Otimizar servicos do Windows";       Desc="Desativa servicos desnecessarios" }
        @{ Key="disable_animations";            Title="Desativar animacoes";                Desc="Remove efeitos visuais para melhor performance" }
        @{ Key="prefetch_superfetch";           Title="Otimizar Prefetch/Superfetch";       Desc="Ajusta servicos de pre-carregamento" }
        @{ Key="disable_telemetry";             Title="Desativar telemetria";               Desc="Reduz coleta de dados do Windows" }
        @{ Key="disable_transparency";          Title="Desativar transparencia";            Desc="Remove efeitos Acrylic" }
        @{ Key="disable_consumer_features";     Title="Desativar recursos de consumidor";   Desc="Remove sugestoes e conteudo promocional" }
        @{ Key="disable_cortana";               Title="Desativar Cortana";                  Desc="Reduz servicos em segundo plano" }
        @{ Key="disable_feedback";              Title="Desativar notif. de feedback";       Desc="Evita pop-ups de feedback" }
        @{ Key="menu_delay_fast";               Title="Acelerar abertura de menus";         Desc="Reduz MenuShowDelay" }
        @{ Key="disable_sticky_keys";           Title="Desativar Sticky Keys";              Desc="Evita ativacao acidental" }
        @{ Key="disable_background_apps";       Title="Bloquear apps em segundo plano";     Desc="Impede apps UWP em background" }
        @{ Key="startup_delay_zero";            Title="Remover atraso de inicializacao";    Desc="Remove delay do Explorer" }
        @{ Key="taskbar_news_off";              Title="Ocultar noticias na barra";          Desc="Desativa noticias e interesses" }
        @{ Key="disable_compat_assistant";      Title="Desativar Compat Assistant";         Desc="Remove pop-ups de compatibilidade" }
        @{ Key="disable_chrome_telemetry";      Title="Desativar Chrome Telemetry";         Desc="Bloqueia metricas do Chrome" }
        @{ Key="disable_nvidia_telemetry";      Title="Desativar NVIDIA Telemetry";         Desc="Desabilita servicos NVIDIA" }
        @{ Key="disable_office_telemetry";      Title="Desativar Office Telemetry";         Desc="Bloqueia telemetria do Office" }
        @{ Key="disable_firefox_telemetry";     Title="Desativar Firefox Telemetry";        Desc="Impede envio de dados" }
        @{ Key="disable_wifi_sense";            Title="Desativar WiFi Sense";               Desc="Bloqueia compartilhamento de redes Wi-Fi" }
        @{ Key="disable_remote_assistance";     Title="Desativar Remote Assistance";        Desc="Remove acesso remoto" }
        @{ Key="disable_windows_tips";          Title="Desativar Windows Tips";             Desc="Remove dicas e sugestoes" }
        @{ Key="disable_location_services";     Title="Desativar Location Services";        Desc="Bloqueia servicos de localizacao" }
        @{ Key="disable_activity_history";      Title="Desativar Activity History";         Desc="Bloqueia historico de atividades e timeline" }
        @{ Key="disable_clipboard_history";     Title="Desativar Clipboard History";        Desc="Remove historico da area de transferencia" }
        @{ Key="disable_advertising_id";        Title="Desativar Advertising ID";           Desc="Bloqueia ID de publicidade" }
        @{ Key="disable_driver_updates";        Title="Desativar Driver Updates";           Desc="Bloqueia updates de driver via WU" }
        @{ Key="disable_windows_spotlight";     Title="Desativar Windows Spotlight";        Desc="Remove imagens da tela de bloqueio" }
        @{ Key="disable_search_web";            Title="Desativar busca web no Iniciar";     Desc="Remove resultados Bing do menu Iniciar" }
        @{ Key="disable_notification_center";   Title="Desativar Centro de Notificacoes";   Desc="Remove Action Center e toasts" }
        @{ Key="disable_edge_telemetry";        Title="Desativar telemetria do Edge";       Desc="Bloqueia coleta de dados do Microsoft Edge" }
        @{ Key="disable_ps_telemetry";          Title="Desativar telemetria do PowerShell"; Desc="Remove logging e transcricao do PS" }
        @{ Key="change_default_terminal";       Title="Trocar Terminal Padrao";             Desc="Define Windows Terminal como padrao" }
        @{ Key="disable_homegroup";             Title="Desativar Homegroup";                Desc="Para servicos do Homegroup" }
        @{ Key="disable_copilot";               Title="Desativar Microsoft Copilot";        Desc="Remove o Copilot da barra de tarefas" }
        @{ Key="disable_tray_notifications";    Title="Desativar Notif. da Bandeja";        Desc="Remove toasts e notificacoes do calendario" }
        @{ Key="optimize_context_menu";         Title="Clique Direito Otimizado";           Desc="Menu classico rapido + remove sombras" }
        @{ Key="reduced_processes";             Title="Processos Reduzidos";                Desc="Para servicos desnecessarios (Xbox preservado)" }
        @{ Key="disable_bg_apps_all";           Title="Desativar Apps em Segundo Plano";    Desc="Bloqueia todos os apps UWP em background" }
    )
    "Games" = @(
        @{ Key="game_mode";                     Title="Game Mode";                          Desc="Otimiza sistema para jogos" }
        @{ Key="fps_boost";                     Title="FPS Boost";                          Desc="Aplica otimizacoes para aumentar FPS" }
        @{ Key="fullscreen_opt";                Title="Fullscreen Optimization";            Desc="Desativa otimizacoes de tela cheia" }
        @{ Key="disable_game_dvr";              Title="Desativar Game DVR";                 Desc="Reduz impacto no FPS" }
        @{ Key="disable_game_bar";              Title="Desativar Xbox Game Bar";            Desc="Evita consumo de recursos" }
        @{ Key="disable_xbox_services";         Title="Desativar servicos Xbox";            Desc="Desativa servicos Xbox em background" }
        @{ Key="optimize_games_systemprofile";  Title="Priorizar tarefas de jogos";         Desc="Ajusta perfil multimidia do Windows" }
        @{ Key="ultra_gaming_mode";             Title="Modo Ultra Gaming";                  Desc="Pacote seguro de ajustes para max FPS" }
        @{ Key="master_gaming_optimization";    Title="Master Gaming Optimization";         Desc="Aplica 10 otimizacoes criticas" }
        @{ Key="optimize_mmcss";                Title="Otimizar MMCSS";                     Desc="Multimedia Class Scheduler para jogos" }
        @{ Key="optimize_gpu_thread_priority";  Title="GPU Thread Priority";                Desc="Aumenta prioridade de threads GPU" }
        @{ Key="disable_defender_realtime";     Title="Pausar Defender (Gaming)";           Desc="Pausa protecao em tempo real (ATENCAO!)" }
        @{ Key="gaming_config_pro";             Title="Melhor Config para Jogos";           Desc="7 tweaks criticos combinados para max FPS" }
        @{ Key="disable_dvr_full";              Title="Desativar DVR Completo";             Desc="Remove todas as flags do Game DVR" }
        @{ Key="disable_fso";                   Title="Desativar FSO";                      Desc="Desativa Fullscreen Optimizations (FSO)" }
    )
    "GameBoost" = @(
        @{ Key="valorant_boost";                Title="Valorant Boost";                     Desc="Prioriza VALORANT e reduz input lag" }
        @{ Key="fortnite_boost";                Title="Fortnite Boost";                     Desc="Prioridade alta + throttling off" }
        @{ Key="fivem_boost";                   Title="FiveM / GTA V Boost";                Desc="Foca em FiveM + GTA5 com prioridade" }
        @{ Key="minecraft_boost";               Title="Minecraft Boost";                    Desc="Prioridade e limpeza de heap" }
        @{ Key="roblox_boost";                  Title="Roblox Boost";                       Desc="Prioriza RobloxPlayerBeta" }
        @{ Key="cs2_boost";                     Title="CS2 / CS:GO Boost";                  Desc="Prioridade alta para Counter-Strike" }
        @{ Key="apex_boost";                    Title="Apex Legends Boost";                 Desc="Prioridade + rede otimizada" }
        @{ Key="lol_boost";                     Title="League of Legends Boost";            Desc="Prioridade + Nagle desativado" }
    )
    "Booster" = @(
        @{ Key="cpu_boost";                     Title="CPU Boost";                          Desc="Ajusta prioridade e afinidade da CPU" }
        @{ Key="ram_cleaner";                   Title="RAM Cleaner";                        Desc="Limpa memoria RAM" }
        @{ Key="gpu_optimize";                  Title="GPU Optimization";                   Desc="Otimiza placa de video" }
        @{ Key="disable_search_index";          Title="Desativar indexacao";                Desc="Desativa WSearch" }
        @{ Key="disable_print_spooler";         Title="Desativar Spooler";                  Desc="Libera recursos de impressao" }
        @{ Key="remove_apps";                   Title="Remover Apps/Bloatware";             Desc="Remove apps pre-instalados" }
        @{ Key="clean_browser_cache";           Title="Limpar Cache Navegadores";           Desc="Limpa cache do Edge, Chrome, Firefox" }
        @{ Key="clean_prefetch";                Title="Limpar Prefetch";                    Desc="Apaga arquivos da pasta Prefetch" }
        @{ Key="disable_fast_startup";          Title="Desativar Fast Startup";             Desc="Evita bugs de driver" }
        @{ Key="optimize_ntfs";                 Title="Otimizar NTFS";                      Desc="Desativa last access + 8.3 naming" }
        @{ Key="disable_error_reporting";       Title="Desativar Error Reporting";          Desc="Remove servico WerSvc" }
        @{ Key="disable_auto_maintenance";      Title="Desativar Manut. Automatica";        Desc="Impede manutencao durante gaming" }
        @{ Key="disable_edge_preloading";       Title="Desativar Edge Preloading";          Desc="Remove pre-carregamento do Edge" }
        @{ Key="disable_onedrive_startup";      Title="Desativar OneDrive Startup";         Desc="Impede OneDrive de iniciar automaticamente" }
        @{ Key="optimize_svchost_split";        Title="Otimizar SvcHost Split";             Desc="Reduz processos svchost separados" }
        @{ Key="optimize_drive_gaming";         Title="SSD e HD Otimizados p/ Jogos";       Desc="NTFS tweaks + SysMain off para max I/O" }
        @{ Key="laptop_power_tweaks";           Title="Ajustes de Energia (Notebook)";      Desc="Otimiza AC e bateria para performance" }
        @{ Key="optimize_intel_cpu";            Title="Otimizar Processadores Intel";       Desc="Speed Shift + sem throttling Intel" }
        @{ Key="disable_hibernation_full";      Title="Desativar Hibernar";                 Desc="Libera espaco do hiberfil.sys" }
        @{ Key="disable_adobe_inet";            Title="Bloquear Erros de Internet Adobe";   Desc="Bloqueia dominios Adobe no hosts" }
        @{ Key="optimize_adobe";                Title="Adobe Otimizado";                    Desc="Desativa updates e telemetria Adobe" }
    )
    "Internet" = @(
        @{ Key="dns_flush";                     Title="Limpar Cache DNS";                   Desc="Remove cache DNS antigo" }
        @{ Key="tcp_optimize";                  Title="Otimizacao Completa de Rede";        Desc="Ajusta TCP/UDP para reduzir latencia" }
        @{ Key="ping_reducer";                  Title="Rede Gaming Pro";                    Desc="QoS avancado para jogos" }
        @{ Key="disable_network_throttling";    Title="Desativar Network Throttling";       Desc="Desativa limitacao de rede" }
        @{ Key="disable_delivery_optimization"; Title="Desativar Delivery Optimization";    Desc="Impede compartilhamento de banda" }
        @{ Key="network_cleaner";               Title="Network Cleaner";                    Desc="Limpa sockets, renova IP, zera caches" }
        @{ Key="reset_winsock";                 Title="Resetar Winsock";                    Desc="Corrige erros de socket" }
        @{ Key="dns_gaming";                    Title="DNS Gaming";                         Desc="Cloudflare + Quad9" }
        @{ Key="disable_nagles";                Title="Desativar Nagle's Algorithm";        Desc="Reduz latencia de pacotes TCP" }
        @{ Key="disable_lso";                   Title="Desativar LSO";                      Desc="Desativa Large Send Offload" }
        @{ Key="disable_p2p_updates";           Title="Desativar Updates P2P";              Desc="Bloqueia updates via P2P" }
        @{ Key="disable_bandwidth_limit";       Title="Remover limite de banda QoS";        Desc="Remove reserva de 20% do QoS" }
        @{ Key="optimize_irp_stack";            Title="Otimizar IRPStackSize";              Desc="Aumenta stack para melhor throughput" }
        @{ Key="disable_ipv6";                  Title="Desativar IPv6";                     Desc="Desativa IPv6 e randomizacao de endereco" }
        @{ Key="disable_teredo";                Title="Desativar Teredo";                   Desc="Para o servico de tunelamento Teredo" }
    )
    "Graphics" = @(
        @{ Key="nvidia_opt";                    Title="NVIDIA Optimizer";                   Desc="Otimiza driver NVIDIA" }
        @{ Key="amd_opt";                       Title="AMD Optimizer";                      Desc="Otimiza driver AMD" }
        @{ Key="enable_hags";                   Title="Habilitar HAGS";                     Desc="Hardware-Accelerated GPU Scheduling" }
        @{ Key="clear_shader_cache";            Title="Limpar cache de shaders";            Desc="Limpa DX/NVIDIA/AMD caches" }
        @{ Key="disable_mpo";                   Title="Desativar MPO";                      Desc="Desativa Multiplane Overlay" }
    )
    "Kernel" = @(
        @{ Key="kernel_dynamic_tick";           Title="Desativar Dynamic Tick";             Desc="BCD disabledynamictick (requer reinicio)" }
        @{ Key="kernel_platform_clock";         Title="Desabilitar Platform Clock";         Desc="Remove HPET, usa TSC (requer reinicio)" }
        @{ Key="kernel_tsc_sync";               Title="TSCSyncPolicy = Enhanced";           Desc="Ajusta sincronizacao TSC" }
        @{ Key="kernel_priority_foreground";    Title="Prioridade Win32: foreground";       Desc="Aumenta prioridade de processos" }
        @{ Key="disable_hpet";                  Title="Desativar HPET Completo";            Desc="Remove HPET via BCD" }
        @{ Key="disable_memory_compression";    Title="Desabilitar Memory Compression";     Desc="Libera CPU desabilitando compressao" }
        @{ Key="optimize_io_priority";          Title="Otimizar I/O Priority";              Desc="Aumenta prioridade de I/O" }
        @{ Key="memory_manager_pro";            Title="Memory Manager Pro";                 Desc="Tweaks de gerenciamento de memoria" }
        @{ Key="cache_manager_pro";             Title="Cache Manager Pro";                  Desc="Ajusta cache para baixa latencia" }
        @{ Key="optimize_ntfs_memory";          Title="Otimizar NTFS Memory";               Desc="Aumenta cache NTFS para 256MB" }
    )
    "Input Lag" = @(
        @{ Key="mouse_optimize";                Title="Mouse Optimization";                 Desc="Reduz latencia do mouse" }
        @{ Key="keyboard_boost";                Title="Keyboard Boost";                     Desc="Otimiza resposta do teclado" }
        @{ Key="disable_mouse_trails";          Title="Desativar trilha do mouse";          Desc="Remove efeito de trilha" }
        @{ Key="optimize_usb_power";            Title="Otimizar USB Power";                 Desc="Desativa suspend seletivo" }
        @{ Key="disable_focus_assist";          Title="Desativar Focus Assist";             Desc="Remove notificacoes" }
        @{ Key="optimize_pcie_aspm";            Title="Otimizar PCIe ASPM";                 Desc="Desabilita power saving PCIe" }
        @{ Key="optimize_audio_latency";        Title="Audio Latency (WASAPI)";             Desc="Reduz latencia de audio" }
        @{ Key="optimize_timer_resolution";     Title="Otimizar Timer Resolution";          Desc="Timer de alta precisao para gaming" }
    )
    "Menu" = @(
        @{ Key="disable_autoplay";              Title="Desativar AutoPlay";                 Desc="Evita AutoPlay em dispositivos" }
        @{ Key="disable_soft_landing";          Title="Desativar dicas do Windows";         Desc="Reduz notificacoes/sugestoes" }
    )
    "Creditos" = @()
}

# ==================== ESTADO DAS OPCOES ====================
$script:OptionStates = @{}
$script:LogMessages = ""

# ==================== INTERFACE WPF ====================
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

[xml]$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="YZHY FPS PSW — Premium Boost • MAX FPS" 
        Height="750" Width="1180"
        WindowStartupLocation="CenterScreen"
        WindowStyle="None" ResizeMode="CanResize" AllowsTransparency="True"
        Background="Transparent"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
    <Window.Resources>
        <!-- Colors -->
        <SolidColorBrush x:Key="BG" Color="#0D1117"/>
        <SolidColorBrush x:Key="Sidebar" Color="#161B22"/>
        <SolidColorBrush x:Key="Card" Color="#1C2128"/>
        <SolidColorBrush x:Key="CardHover" Color="#252C35"/>
        <SolidColorBrush x:Key="Accent" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="AccentGreen" Color="#3FB950"/>
        <SolidColorBrush x:Key="AccentOrange" Color="#D29922"/>
        <SolidColorBrush x:Key="AccentRed" Color="#F85149"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#E6EDF3"/>
        <SolidColorBrush x:Key="TextMuted" Color="#6E7681"/>
        <SolidColorBrush x:Key="Border" Color="#21262D"/>
        <SolidColorBrush x:Key="ToggleOff" Color="#30363D"/>
        <SolidColorBrush x:Key="TitleBarBG" Color="#010409"/>

        <!-- Sidebar Button -->
        <Style x:Key="SidebarBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="14,10"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#1C2128"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Toggle Style -->
        <Style x:Key="ToggleSwitch" TargetType="CheckBox">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <Grid>
                            <Border x:Name="track" Width="44" Height="24" CornerRadius="12" Background="{StaticResource ToggleOff}" Cursor="Hand"/>
                            <Border x:Name="thumb" Width="18" Height="18" CornerRadius="9" Background="#8B949E" HorizontalAlignment="Left" Margin="3,0,0,0" VerticalAlignment="Center"/>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="track" Property="Background" Value="{StaticResource Accent}"/>
                                <Setter TargetName="thumb" Property="Background" Value="#161B22"/>
                                <Setter TargetName="thumb" Property="Margin" Value="23,0,0,0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Apply All Button -->
        <Style x:Key="ApplyAllBtn" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="#0D1117"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="20,10"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="10" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#D8D8D8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- TitleBar Button -->
        <Style x:Key="TitleBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="Width" Value="36"/>
            <Setter Property="Height" Value="36"/>
            <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
            <Setter Property="FontSize" Value="10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#1C2128"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="CloseBtn" TargetType="Button" BasedOn="{StaticResource TitleBtn}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="Transparent" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#DA3633"/>
                                <Setter TargetName="bd" Property="TextElement.Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Modern Thin ScrollBar -->
        <Style TargetType="ScrollBar">
            <Setter Property="Width" Value="6"/>
            <Setter Property="MinWidth" Value="6"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ScrollBar">
                        <Grid>
                            <Border Background="Transparent" CornerRadius="3"/>
                            <Track x:Name="PART_Track" IsDirectionReversed="True" Focusable="False">
                                <Track.DecreaseRepeatButton>
                                    <RepeatButton Opacity="0" Focusable="False" IsHitTestVisible="False"/>
                                </Track.DecreaseRepeatButton>
                                <Track.Thumb>
                                    <Thumb>
                                        <Thumb.Template>
                                            <ControlTemplate TargetType="Thumb">
                                                <Border x:Name="bd" Background="#3E454F" CornerRadius="3" Margin="1"/>
                                                <ControlTemplate.Triggers>
                                                    <Trigger Property="IsMouseOver" Value="True">
                                                        <Setter TargetName="bd" Property="Background" Value="#8B949E"/>
                                                    </Trigger>
                                                    <Trigger Property="IsDragging" Value="True">
                                                        <Setter TargetName="bd" Property="Background" Value="#B0B8C1"/>
                                                    </Trigger>
                                                </ControlTemplate.Triggers>
                                            </ControlTemplate>
                                        </Thumb.Template>
                                    </Thumb>
                                </Track.Thumb>
                                <Track.IncreaseRepeatButton>
                                    <RepeatButton Opacity="0" Focusable="False" IsHitTestVisible="False"/>
                                </Track.IncreaseRepeatButton>
                            </Track>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Border CornerRadius="14" BorderBrush="{StaticResource Border}" BorderThickness="1" Background="{StaticResource BG}">
        <Border.Effect>
            <DropShadowEffect BlurRadius="20" ShadowDepth="0" Opacity="0.5" Color="Black"/>
        </Border.Effect>
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="44"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <!-- Title Bar -->
            <Border Grid.Row="0" Background="{StaticResource TitleBarBG}" CornerRadius="14,14,0,0" Name="TitleBar">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="12,0,0,0">
                        <Border Width="26" Height="26" CornerRadius="6" ClipToBounds="True" Margin="0,0,10,0" VerticalAlignment="Center">
                            <Image Name="TitleBarLogo" Stretch="UniformToFill" RenderOptions.BitmapScalingMode="HighQuality"/>
                        </Border>
                        <TextBlock Text="YZHY FPS PSW" FontWeight="Bold" FontSize="14" Foreground="{StaticResource TextPrimary}"/>
                        <TextBlock Text=" • Premium Boost • MAX FPS • PowerShell Edition" FontSize="11" Foreground="{StaticResource TextMuted}" VerticalAlignment="Center" Margin="8,0,0,0"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1" Orientation="Horizontal" Margin="0,0,6,0" VerticalAlignment="Center">
                        <Button Style="{StaticResource TitleBtn}" Content="&#xE921;" Name="MinBtn"/>
                        <Button Style="{StaticResource TitleBtn}" Content="&#xE922;" Name="MaxBtn" Margin="4,0"/>
                        <Button Style="{StaticResource CloseBtn}" Content="&#xE8BB;" Name="CloseBtn"/>
                    </StackPanel>
                </Grid>
            </Border>

            <!-- Main Content -->
            <Grid Grid.Row="1">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="230"/>
                    <ColumnDefinition/>
                </Grid.ColumnDefinitions>

                <!-- Sidebar -->
                <Border Grid.Column="0" Background="{StaticResource Sidebar}" BorderBrush="{StaticResource Border}" BorderThickness="0,0,1,0" CornerRadius="0,0,0,14">
                    <DockPanel Margin="16,20">
                        <!-- Logo -->
                        <StackPanel DockPanel.Dock="Top">
                            <Image Name="LogoImg" Height="62" HorizontalAlignment="Left" Stretch="Uniform" RenderOptions.BitmapScalingMode="HighQuality"/>
                            <TextBlock Text="YZHY FPS PSW" FontSize="17" FontWeight="Bold" Margin="0,10,0,0" Foreground="{StaticResource TextPrimary}"/>
                            <TextBlock Name="AdminLabel" Text="Verificando..." Foreground="{StaticResource TextMuted}" FontSize="10" Margin="0,4,0,0"/>
                            <TextBlock Text="Build 2026 • PowerShell Edition" Foreground="{StaticResource TextMuted}" FontSize="10" Margin="0,2,0,0"/>
                        </StackPanel>

                        <!-- Nav Buttons -->
                        <ScrollViewer DockPanel.Dock="Top" Margin="0,18,0,0" VerticalScrollBarVisibility="Auto">
                            <StackPanel Name="NavPanel" Margin="0,0,4,0"/>
                        </ScrollViewer>
                    </DockPanel>
                </Border>

                <!-- Content Area -->
                <Grid Grid.Column="1" Margin="0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Header -->
                    <Border Grid.Row="0" Padding="28,18,28,12">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel>
                                <TextBlock Name="CategoryTitle" Text="Sistema" FontSize="22" FontWeight="Bold" Foreground="{StaticResource TextPrimary}"/>
                                <TextBlock Name="CategoryDesc" Text="Otimizacoes do sistema operacional" FontSize="12" Foreground="{StaticResource TextMuted}" Margin="0,4,0,0"/>
                            </StackPanel>
                            <Button Grid.Column="1" Style="{StaticResource ApplyAllBtn}" Content="⚡ Run Tweaks" Name="ApplyAllBtn" VerticalAlignment="Center"/>
                        </Grid>
                    </Border>

                    <!-- Options List -->
                    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="28,0,28,10">
                        <StackPanel Name="OptionsPanel"/>
                    </ScrollViewer>

                    <!-- Status Bar -->
                    <Border Grid.Row="2" Background="{StaticResource Sidebar}" Padding="20,10" CornerRadius="0,0,14,0" BorderBrush="{StaticResource Border}" BorderThickness="0,1,0,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Name="StatusText" Text="Pronto" Foreground="{StaticResource TextMuted}" FontSize="11" VerticalAlignment="Center"/>
                            <TextBlock Grid.Column="1" Name="CounterText" Text="0 ativas" Foreground="{StaticResource Accent}" FontSize="11" VerticalAlignment="Center" Margin="0,0,16,0"/>
                            <TextBlock Grid.Column="2" Name="VersionText" Text="v2.0 PSW" Foreground="{StaticResource TextMuted}" FontSize="11" VerticalAlignment="Center"/>
                        </Grid>
                    </Border>
                </Grid>
            </Grid>

            <!-- Progress Popup Overlay -->
            <Grid Name="ProgressOverlay" Grid.RowSpan="2" Visibility="Collapsed">
                <Border Background="#CC000000" CornerRadius="14"/>
                <Border Background="#161B22" CornerRadius="14" MaxWidth="420" MinWidth="320"
                        HorizontalAlignment="Center" VerticalAlignment="Center"
                        BorderBrush="#30363D" BorderThickness="1" Padding="38,32,38,32">
                    <Border.Effect>
                        <DropShadowEffect BlurRadius="40" ShadowDepth="0" Opacity="0.85" Color="Black"/>
                    </Border.Effect>
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                            <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                                       Foreground="#FFFFFF" VerticalAlignment="Center" Margin="0,0,10,0"/>
                            <TextBlock Text="Processando" FontSize="16" FontWeight="Bold"
                                       Foreground="#E6EDF3" VerticalAlignment="Center"/>
                        </StackPanel>
                        <TextBlock Name="PopupTitleText" Text="" FontSize="13" FontWeight="SemiBold"
                                   Foreground="#FFFFFF" HorizontalAlignment="Center"
                                   Margin="0,12,0,0" TextWrapping="Wrap" MaxWidth="340" TextAlignment="Center"/>
                        <TextBlock Name="PopupStatusText" Text="Aguarde..." FontSize="11"
                                   Foreground="#6E7681" HorizontalAlignment="Center"
                                   Margin="0,6,0,0" TextWrapping="Wrap" MaxWidth="340" TextAlignment="Center"/>
                        <!-- Current command label -->
                        <Border Background="#0D1117" CornerRadius="6" Padding="10,6" Margin="0,10,0,0">
                            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                                <TextBlock Text="&#xE756;" FontFamily="Segoe MDL2 Assets" FontSize="11"
                                           Foreground="#3FB950" VerticalAlignment="Center" Margin="0,0,6,0"/>
                                <TextBlock Name="PopupCurrentCmd" Text="Aguardando..." FontSize="11"
                                           Foreground="#3FB950" TextWrapping="Wrap" MaxWidth="280"
                                           VerticalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                        <Grid Margin="0,16,0,6" Height="4" Width="300">
                            <Border Background="#21262D" CornerRadius="2"/>
                            <Border Name="PopupProgressFill" Background="#FFFFFF" CornerRadius="2"
                                    HorizontalAlignment="Left" Width="0"/>
                        </Grid>
                        <TextBlock Name="PopupProgressLabel" Text="" FontSize="11"
                                   Foreground="#6E7681" HorizontalAlignment="Center"/>
                    </StackPanel>
                </Border>
            </Grid>

            <!-- Loading / Splash Screen Overlay -->
            <Grid Name="LoadingOverlay" Grid.RowSpan="2" Visibility="Visible">
                <!-- Pure black, zero blue tint -->
                <Border Background="#000000"/>
                <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                    <!-- VarejoCode logo — PNG transparent, no frame -->
                    <Image Name="SplashLogoImg" Height="100" HorizontalAlignment="Center"
                           Stretch="Uniform" RenderOptions.BitmapScalingMode="HighQuality"
                           Margin="0,0,0,32"/>
                    <!-- Spinning loader ring -->
                    <Grid Width="52" Height="52" HorizontalAlignment="Center" Margin="0,0,0,32">
                        <Ellipse Stroke="#1E1E1E" StrokeThickness="4"/>
                        <Ellipse Name="SplashSpinner" Stroke="#FFFFFF" StrokeThickness="4"
                                 StrokeDashArray="28 12"
                                 RenderTransformOrigin="0.5,0.5">
                            <Ellipse.RenderTransform>
                                <RotateTransform Angle="0"/>
                            </Ellipse.RenderTransform>
                        </Ellipse>
                    </Grid>
                    <TextBlock Text="Powered by" FontSize="11" Foreground="#444444"
                               HorizontalAlignment="Center" Margin="0,0,0,4"/>
                    <TextBlock Text="VarejoCode" FontSize="28" FontWeight="Bold"
                               Foreground="#FFFFFF" HorizontalAlignment="Center" Margin="0,0,0,22"/>
                    <Border Background="#1A1A1A" Height="1" HorizontalAlignment="Stretch" Margin="0,0,0,16"/>
                    <TextBlock Name="SplashWebBtn" Text="www.varejocode.com.br"
                               FontSize="12" Foreground="#999999" HorizontalAlignment="Center"
                               Cursor="Hand" TextDecorations="Underline" Margin="0,0,0,8"/>
                    <TextBlock Name="SplashDiscordVarejo" Text="Discord VarejoCode"
                               FontSize="12" Foreground="#7289DA" HorizontalAlignment="Center"
                               Cursor="Hand" TextDecorations="Underline" Margin="0,0,0,6"/>
                    <TextBlock Name="SplashDiscordYzhy" Text="Discord Yzhy Tweaks"
                               FontSize="12" Foreground="#7289DA" HorizontalAlignment="Center"
                               Cursor="Hand" TextDecorations="Underline"/>
                </StackPanel>
            </Grid>

            <!-- Login Overlay — shown after splash, hidden after correct password -->
            <Grid Name="LoginOverlay" Grid.RowSpan="2" Visibility="Collapsed" Opacity="0">
                <Border Background="#0D1117"/>
                <Border HorizontalAlignment="Center" VerticalAlignment="Center"
                        Background="#161B22" CornerRadius="18"
                        BorderBrush="#30363D" BorderThickness="1"
                        Padding="52,44,52,44" MinWidth="380">
                    <Border.Effect>
                        <DropShadowEffect BlurRadius="60" ShadowDepth="0" Opacity="0.9" Color="Black"/>
                    </Border.Effect>
                    <StackPanel>
                        <!-- Lock icon -->
                        <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="36"
                                   Foreground="#FFFFFF" HorizontalAlignment="Center" Margin="0,0,0,14"/>
                        <!-- Title -->
                        <TextBlock Text="YZHY FPS PSW" FontSize="22" FontWeight="Bold"
                                   Foreground="#E6EDF3" HorizontalAlignment="Center" Margin="0,0,0,4"/>
                        <TextBlock Text="Digite a senha de acesso" FontSize="12"
                                   Foreground="#6E7681" HorizontalAlignment="Center" Margin="0,0,0,28"/>
                        <!-- Password box -->
                        <Border Name="LoginFieldBorder" Background="#1C2128" CornerRadius="10"
                                BorderBrush="#30363D" BorderThickness="1.5" Margin="0,0,0,10"
                                ClipToBounds="True">
                            <Grid Margin="14,0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                           Foreground="#6E7681" VerticalAlignment="Center" Margin="0,0,10,0"
                                           Grid.Column="0"/>
                                <PasswordBox Name="LoginPasswordBox" Grid.Column="1"
                                             FontSize="15" Height="46"
                                             Background="Transparent" BorderThickness="0"
                                             Foreground="#E6EDF3" CaretBrush="#FFFFFF"
                                             PasswordChar="&#x2022;"
                                             VerticalContentAlignment="Center"
                                             Padding="2,0,0,0"
                                             FocusVisualStyle="{x:Null}"/>
                            </Grid>
                        </Border>
                        <!-- Error message -->
                        <TextBlock Name="LoginErrorText" Text="" FontSize="12"
                                   Foreground="#F85149" HorizontalAlignment="Center"
                                   Margin="0,0,0,14" Visibility="Collapsed"/>
                        <!-- Login button -->
                        <Button Name="LoginBtn" Height="46" Margin="0,4,0,0"
                                Cursor="Hand" BorderThickness="0">
                            <Button.Template>
                                <ControlTemplate TargetType="Button">
                                    <Border x:Name="bd" Background="#FFFFFF" CornerRadius="10">
                                        <TextBlock Text="Entrar" FontSize="14" FontWeight="Bold"
                                                   Foreground="#0D1117" HorizontalAlignment="Center"
                                                   VerticalAlignment="Center"/>
                                    </Border>
                                    <ControlTemplate.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter TargetName="bd" Property="Background" Value="#D8D8D8"/>
                                        </Trigger>
                                        <Trigger Property="IsPressed" Value="True">
                                            <Setter TargetName="bd" Property="Background" Value="#B8B8B8"/>
                                        </Trigger>
                                    </ControlTemplate.Triggers>
                                </ControlTemplate>
                            </Button.Template>
                        </Button>
                        <!-- Footer hint -->
                        <TextBlock Text="Powered by VarejoCode" FontSize="10"
                                   Foreground="#3E454F" HorizontalAlignment="Center" Margin="0,22,0,0"/>
                    </StackPanel>
                </Border>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

# Parse XAML
$reader = New-Object System.Xml.XmlNodeReader $XAML
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Get controls
$TitleBar       = $Window.FindName("TitleBar")
$MinBtn         = $Window.FindName("MinBtn")
$MaxBtn         = $Window.FindName("MaxBtn")
$CloseBtn       = $Window.FindName("CloseBtn")
$NavPanel       = $Window.FindName("NavPanel")
$OptionsPanel   = $Window.FindName("OptionsPanel")
$CategoryTitle  = $Window.FindName("CategoryTitle")
$CategoryDesc   = $Window.FindName("CategoryDesc")
$ApplyAllBtn    = $Window.FindName("ApplyAllBtn")
$AdminLabel     = $Window.FindName("AdminLabel")
$StatusText     = $Window.FindName("StatusText")
$CounterText    = $Window.FindName("CounterText")
$VersionText    = $Window.FindName("VersionText")
$LogoImg             = $Window.FindName("LogoImg")
$TitleBarLogo        = $Window.FindName("TitleBarLogo")
$ProgressOverlay     = $Window.FindName("ProgressOverlay")
$PopupTitleText      = $Window.FindName("PopupTitleText")
$PopupStatusText     = $Window.FindName("PopupStatusText")
$PopupProgressFill   = $Window.FindName("PopupProgressFill")
$PopupProgressLabel  = $Window.FindName("PopupProgressLabel")
$PopupCurrentCmd     = $Window.FindName("PopupCurrentCmd")
$LoadingOverlay      = $Window.FindName("LoadingOverlay")
$SplashLogoImg       = $Window.FindName("SplashLogoImg")
$SplashSpinner       = $Window.FindName("SplashSpinner")
$SplashDiscordVarejo = $Window.FindName("SplashDiscordVarejo")
$SplashDiscordYzhy   = $Window.FindName("SplashDiscordYzhy")
$SplashWebBtn        = $Window.FindName("SplashWebBtn")
$LoginOverlay        = $Window.FindName("LoginOverlay")
$LoginPasswordBox    = $Window.FindName("LoginPasswordBox")
$LoginBtn            = $Window.FindName("LoginBtn")
$LoginErrorText      = $Window.FindName("LoginErrorText")
$LoginFieldBorder    = $Window.FindName("LoginFieldBorder")

# Admin label
if ($script:IsAdmin) {
    $AdminLabel.Text = "$([char]0x2713) Executando como Administrador"
    $AdminLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#3FB950")
} else {
    $AdminLabel.Text = "$([char]0x26A0) Sem privilegios de administrador"
    $AdminLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#D29922")
}

# Load YZHY logo from GitHub
try {
    $req = [System.Net.WebRequest]::Create("https://raw.githubusercontent.com/matheusdamoda4-sudo/YzhyFPSREPO/refs/heads/main/Assets/yzhylogo.jpg")
    $req.Timeout = 6000
    $resp    = $req.GetResponse()
    $rStream = $resp.GetResponseStream()
    $ms      = New-Object System.IO.MemoryStream
    $rStream.CopyTo($ms)
    $resp.Close()
    $ms.Position = 0
    $bmpLogo = New-Object System.Windows.Media.Imaging.BitmapImage
    $bmpLogo.BeginInit()
    $bmpLogo.StreamSource = $ms
    $bmpLogo.CacheOption  = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $bmpLogo.EndInit()
    $bmpLogo.Freeze()
    $ms.Close()
    if ($LogoImg)      { $LogoImg.Source      = $bmpLogo }
    if ($TitleBarLogo) { $TitleBarLogo.Source  = $bmpLogo }
} catch {}

# Load VarejoCode logo for splash (PNG with transparent background)
try {
    $vcReq    = [System.Net.WebRequest]::Create("https://varejocode.com.br/logo.png")
    $vcReq.Timeout = 6000
    $vcResp   = $vcReq.GetResponse()
    $vcStream = $vcResp.GetResponseStream()
    $vcMs     = New-Object System.IO.MemoryStream
    $vcStream.CopyTo($vcMs)
    $vcResp.Close()
    $vcMs.Position = 0
    $bmpVarejo = New-Object System.Windows.Media.Imaging.BitmapImage
    $bmpVarejo.BeginInit()
    $bmpVarejo.StreamSource = $vcMs
    $bmpVarejo.CacheOption  = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $bmpVarejo.EndInit()
    $bmpVarejo.Freeze()
    $vcMs.Close()
    if ($SplashLogoImg) { $SplashLogoImg.Source = $bmpVarejo }
} catch {}

# Spinner — DispatcherTimer animates the RotateTransform on SplashSpinner
$script:_splashAngle = 0
$spinTimer = $null
if ($SplashSpinner) {
    $spinRot   = [System.Windows.Media.RotateTransform]$SplashSpinner.RenderTransform
    $spinTimer = New-Object System.Windows.Threading.DispatcherTimer
    $spinTimer.Interval = [TimeSpan]::FromMilliseconds(16)   # ~60 fps
    $spinTimer.Add_Tick({
        $script:_splashAngle = ($script:_splashAngle + 6) % 360
        $spinRot.Angle = $script:_splashAngle
    }.GetNewClosure())
    $spinTimer.Start()
}

# Title bar drag
$TitleBar.Add_MouseLeftButtonDown({ $Window.DragMove() })

# Window buttons
$MinBtn.Add_Click({ $Window.WindowState = 'Minimized' })
$MaxBtn.Add_Click({
    if ($Window.WindowState -eq 'Maximized') { $Window.WindowState = 'Normal' }
    else { $Window.WindowState = 'Maximized' }
})
$CloseBtn.Add_Click({ $Window.Close() })

# Current category
$script:CurrentCategory = "Sistema"

# Category descriptions
$script:CategoryDescriptions = @{
    "Sistema"    = "Otimizacoes do sistema operacional"
    "Games"      = "Otimizacoes especificas para jogos"
    "GameBoost"  = "Boost para jogos especificos"
    "Booster"    = "Limpeza e boost de desempenho"
    "Internet"   = "Otimizacoes de rede e conectividade"
    "Graphics"   = "Otimizacoes de placa de video"
    "Kernel"     = "Otimizacoes avancadas do kernel (ATENCAO!)"
    "Input Lag"  = "Reducao de latencia de entrada"
    "Menu"       = "Configuracoes e utilitarios"
    "Creditos"   = "Sobre o app e a equipe por tras"
}

# Category icons
$script:CategoryIcons = @{
    "Sistema"    = [char]0xE770
    "Games"      = [char]0xE7FC
    "GameBoost"  = [char]0xE9CA
    "Booster"    = [char]0xE9CA
    "Internet"   = [char]0xE774
    "Graphics"   = [char]0xED43
    "Kernel"     = [char]0xE713
    "Input Lag"  = [char]0xEA3A
    "Menu"       = [char]0xE700
    "Creditos"   = [char]0xE734
}

# Category badge colors
$script:CategoryBadgeColors = @{
    "Sistema"    = "#FFFFFF"
    "Games"      = "#FFFFFF"
    "GameBoost"  = "#FFFFFF"
    "Booster"    = "#FFFFFF"
    "Internet"   = "#FFFFFF"
    "Graphics"   = "#FFFFFF"
    "Kernel"     = "#FF9500"
    "Input Lag"  = "#FFFFFF"
    "Menu"       = "#FFFFFF"
    "Creditos"   = "#FFFFFF"
}

# ── UI helpers exposed globally for optimization functions ───────────────
function Set-PopupStep {
    param([string]$Step)
    if ($PopupCurrentCmd) { $PopupCurrentCmd.Text = $Step }
    if ($StatusText)      { $StatusText.Text = $Step }
    Invoke-UIFlush
}

function Set-PopupProgress {
    param([double]$Fraction)   # 0.0 – 1.0
    if (-not $PopupProgressFill) { return }
    $targetW = [Math]::Round(300 * [Math]::Max(0,[Math]::Min(1,$Fraction)))
    $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $anim.To       = $targetW
    $anim.Duration = [System.Windows.Duration]([TimeSpan]::FromMilliseconds(280))
    $easing = New-Object System.Windows.Media.Animation.CubicEase
    $easing.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseOut
    $anim.EasingFunction = $easing
    $PopupProgressFill.BeginAnimation([System.Windows.Controls.Border]::WidthProperty, $anim)
}

function Update-Counter {
    $count = ($script:OptionStates.Values | Where-Object { $_ -eq $true }).Count
    $CounterText.Text = "$count ativas"
}

function Build-CreditsUI {
    $ApplyAllBtn.Visibility = "Collapsed"
    $OptionsPanel.Children.Clear()

    # ── Helper: create a styled card ──────────────────────────────────────
    function New-CreditCard($titleText, $descText) {
        $card = New-Object System.Windows.Controls.Border
        $card.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#1C2128")
        $card.CornerRadius = [System.Windows.CornerRadius]::new(12)
        $card.Padding = [System.Windows.Thickness]::new(24, 20, 24, 20)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
        $card.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#30363D")
        $card.BorderThickness = [System.Windows.Thickness]::new(1)
        $sp = New-Object System.Windows.Controls.StackPanel
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = $titleText
        $t.FontSize = 18 ; $t.FontWeight = "Bold"
        $t.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#E6EDF3")
        $t.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $sp.Children.Add($t)
        $d = New-Object System.Windows.Controls.TextBlock
        $d.Text = $descText ; $d.FontSize = 12 ; $d.TextWrapping = "Wrap"
        $d.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
        $d.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
        $sp.Children.Add($d)
        $card.Child = $sp
        return @{ Card = $card; Stack = $sp }
    }

    # Helper: create a link button
    function New-LinkBtn($label, $url) {
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $label
        $b.Style = $Window.Resources["ApplyAllBtn"]
        $b.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
        $capturedUrl = $url
        $b.Add_Click({ Start-Process $capturedUrl }.GetNewClosure())
        return $b
    }

    # ── VarejoCode card ───────────────────────────────────────────────────
    $vc = New-CreditCard "VarejoCode" "Plataforma responsavel pelo desenvolvimento e distribuicao deste produto. Acesse nosso site e junte-se a comunidade!"
    $vcBtnSp = New-Object System.Windows.Controls.StackPanel
    $vcBtnSp.Orientation = "Horizontal"
    $vcBtnSp.Children.Add((New-LinkBtn "Site: varejocode.com.br" "https://varejocode.com.br"))
    $vcBtnSp.Children.Add((New-LinkBtn "Discord VarejoCode" "https://discord.gg/gyHSQTNcp6"))
    $vc.Stack.Children.Add($vcBtnSp)
    $OptionsPanel.Children.Add($vc.Card)

    # ── Yzhy Tweaks card ──────────────────────────────────────────────────
    $yz = New-CreditCard "Yzhy Tweaks" "Comunidade dedicada a tweaks e otimizacoes para jogos e desempenho do Windows. Junte-se e maximize seu PC!"
    $yz.Stack.Children.Add((New-LinkBtn "Discord Yzhy Tweaks" "https://discord.gg/3eP4txtKNb"))
    $OptionsPanel.Children.Add($yz.Card)

    # ── Footer ────────────────────────────────────────────────────────────
    $foot = New-Object System.Windows.Controls.TextBlock
    $foot.Text = "Feito com amor por VarejoCode x Yzhy Tweaks  |  v2.0 PSW  |  2026"
    $foot.FontSize = 11
    $foot.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#3E454F")
    $foot.HorizontalAlignment = "Center"
    $foot.Margin = [System.Windows.Thickness]::new(0, 12, 0, 4)
    $foot.TextWrapping = "Wrap" ; $foot.TextAlignment = "Center"
    $OptionsPanel.Children.Add($foot)
}

function Build-OptionsUI {
    param([string]$Category)
    
    $OptionsPanel.Children.Clear()
    if ($Category -eq "Creditos") { Build-CreditsUI; return }
    $ApplyAllBtn.Visibility = "Visible"
    $items = $script:Categories[$Category]
    if (-not $items) { return }

    foreach ($item in $items) {
        $key = $item.Key
        $title = $item.Title
        $desc = $item.Desc

        # Card Border
        $card = New-Object System.Windows.Controls.Border
        $card.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#1C2128")
        $card.CornerRadius = [System.Windows.CornerRadius]::new(10)
        $card.Padding = [System.Windows.Thickness]::new(18, 14, 18, 14)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $card.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#30363D")
        $card.BorderThickness = [System.Windows.Thickness]::new(1)
        
        # Hover effect
        $card.Add_MouseEnter({
            $this.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#252C35")
        })
        $card.Add_MouseLeave({
            $this.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#1C2128")
        })

        # Grid layout
        $grid = New-Object System.Windows.Controls.Grid
        $col1 = New-Object System.Windows.Controls.ColumnDefinition
        $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $col2 = New-Object System.Windows.Controls.ColumnDefinition
        $col2.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $grid.ColumnDefinitions.Add($col1)
        $grid.ColumnDefinitions.Add($col2)

        # Title + Description
        $textPanel = New-Object System.Windows.Controls.StackPanel
        [System.Windows.Controls.Grid]::SetColumn($textPanel, 0)
        
        $titleTb = New-Object System.Windows.Controls.TextBlock
        $titleTb.Text = $title
        $titleTb.FontSize = 13.5
        $titleTb.FontWeight = "SemiBold"
        $titleTb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#E6EDF3")
        $textPanel.Children.Add($titleTb)

        $descTb = New-Object System.Windows.Controls.TextBlock
        $descTb.Text = $desc
        $descTb.FontSize = 11
        $descTb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
        $descTb.Margin = [System.Windows.Thickness]::new(0, 3, 0, 0)
        $textPanel.Children.Add($descTb)

        # Status label
        $statusTb = New-Object System.Windows.Controls.TextBlock
        $statusTb.Name = "Status_$($key -replace '[^a-zA-Z0-9]','_')"
        $statusTb.Text = "Pronto"
        $statusTb.FontSize = 10
        $statusTb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
        $statusTb.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0)
        $textPanel.Children.Add($statusTb)

        $grid.Children.Add($textPanel)

        # Toggle switch
        $toggle = New-Object System.Windows.Controls.CheckBox
        $toggle.Style = $Window.Resources["ToggleSwitch"]
        $toggle.VerticalAlignment = "Center"
        $toggle.Tag = $key
        $toggle.IsChecked = ($script:OptionStates[$key] -eq $true)
        [System.Windows.Controls.Grid]::SetColumn($toggle, 1)

        # Capture references for GetNewClosure (avoids $script: scope issues inside closures)
        $capturedStatus  = $statusTb
        $capturedTitle   = $title
        $capturedStates  = $script:OptionStates
        $capturedMap     = $script:OptimizationMap

        $toggle.Add_Checked({
            $k = $this.Tag
            $capturedStates[$k] = $true
            $capturedStatus.Text       = "Selecionado"
            $capturedStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#58A6FF")
            Update-Counter
            Update-NavBadges
        }.GetNewClosure())

        $toggle.Add_Unchecked({
            $k = $this.Tag
            $capturedStates[$k] = $false
            $capturedStatus.Text       = "Inativo"
            $capturedStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
            Update-Counter
            Update-NavBadges
        }.GetNewClosure())

        $grid.Children.Add($toggle)
        $card.Child = $grid
        $OptionsPanel.Children.Add($card)
    }
}

function Navigate-Category {
    param([string]$Category)
    $script:CurrentCategory = $Category
    $CategoryTitle.Text = $Category
    $CategoryDesc.Text = $script:CategoryDescriptions[$Category]
    Build-OptionsUI $Category
    
    # Highlight active nav button
    foreach ($child in $NavPanel.Children) {
        if ($child -is [System.Windows.Controls.Button]) {
            if ($child.Tag -eq $Category) {
                $child.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#252C35")
                $child.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#FFFFFF")
            } else {
                $child.Background = [System.Windows.Media.Brushes]::Transparent
                $child.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
            }
        }
    }
}

function Get-CategoryActiveCount {
    param([string]$Category)
    $items = $script:Categories[$Category]
    if (-not $items) { return 0 }
    $count = 0
    foreach ($item in $items) {
        if ($script:OptionStates[$item.Key] -eq $true) { $count++ }
    }
    return $count
}

$script:NavBadges = @{}

function Update-NavBadges {
    foreach ($cat in $script:Categories.Keys) {
        $count = Get-CategoryActiveCount $cat
        $badge = $script:NavBadges[$cat]
        if ($badge) {
            if ($count -gt 0) {
                $badge.Visibility = "Visible"
                $badgeText = $badge.Child
                if ($badgeText) { $badgeText.Text = "$count" }
            } else {
                $badge.Visibility = "Collapsed"
            }
        }
    }
}

# Build navigation
foreach ($cat in $script:Categories.Keys) {
    $btn = New-Object System.Windows.Controls.Button
    $btn.Style = $Window.Resources["SidebarBtn"]
    $btn.Tag = $cat
    $btn.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)

    $btnGrid = New-Object System.Windows.Controls.Grid
    $bgCol1 = New-Object System.Windows.Controls.ColumnDefinition
    $bgCol1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bgCol2 = New-Object System.Windows.Controls.ColumnDefinition
    $bgCol2.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $btnGrid.ColumnDefinitions.Add($bgCol1)
    $btnGrid.ColumnDefinitions.Add($bgCol2)

    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = "Horizontal"
    [System.Windows.Controls.Grid]::SetColumn($sp, 0)

    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text = $script:CategoryIcons[$cat]
    $icon.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe MDL2 Assets")
    $icon.FontSize = 16
    $icon.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#8B949E")
    $icon.VerticalAlignment = "Center"
    $sp.Children.Add($icon)

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $cat
    $label.Margin = [System.Windows.Thickness]::new(10, 0, 0, 0)
    $label.VerticalAlignment = "Center"
    $label.FontSize = 13
    $sp.Children.Add($label)

    $btnGrid.Children.Add($sp)

    # Badge
    $badge = New-Object System.Windows.Controls.Border
    $badge.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom($script:CategoryBadgeColors[$cat])
    $badge.CornerRadius = [System.Windows.CornerRadius]::new(8)
    $badge.Padding = [System.Windows.Thickness]::new(6, 1, 6, 1)
    $badge.MinWidth = 20
    $badge.VerticalAlignment = "Center"
    $badge.HorizontalAlignment = "Right"
    $badge.Visibility = "Collapsed"
    [System.Windows.Controls.Grid]::SetColumn($badge, 1)

    $badgeText = New-Object System.Windows.Controls.TextBlock
    $badgeText.Text = "0"
    $badgeText.FontSize = 10
    $badgeText.FontWeight = "Bold"
    $badgeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#0D1117")
    $badgeText.HorizontalAlignment = "Center"
    $badge.Child = $badgeText
    $btnGrid.Children.Add($badge)
    $script:NavBadges[$cat] = $badge

    $btn.Content = $btnGrid

    $capturedCat = $cat
    $btn.Add_Click({
        Navigate-Category $capturedCat
    }.GetNewClosure())

    $NavPanel.Children.Add($btn)
}

# Apply All button
$ApplyAllBtn.Add_Click({
    $catName     = $script:CurrentCategory
    $items       = $script:Categories[$catName]
    if (-not $items) { return }
    $localStates = $script:OptionStates
    $localMap    = $script:OptimizationMap

    # Only run items that are currently checked
    $selected = $items | Where-Object { $localStates[$_.Key] -eq $true }
    $total    = $selected.Count

    if ($total -eq 0) {
        $StatusText.Text = "Nenhuma opcao selecionada. Marque os toggles primeiro."
        return
    }

    $current = 0
    $success = 0

    # Show progress popup
    $PopupTitleText.Text     = "Run Tweaks: $catName"
    $PopupStatusText.Text    = "Iniciando..."
    $PopupCurrentCmd.Text    = "Preparando..."
    $PopupProgressLabel.Text = "0 / $total"
    $ProgressOverlay.Visibility = "Visible"
    Set-PopupProgress 0
    Invoke-UIFlush

    foreach ($item in $selected) {
        $current++
        $key = $item.Key
        $PopupStatusText.Text    = $item.Title
        $PopupCurrentCmd.Text    = "Rodando: $($item.Title)"
        $PopupProgressLabel.Text = "$current / $total"
        $StatusText.Text         = "[$current/$total] $($item.Title)..."
        Set-PopupProgress (($current - 1) / $total)
        Invoke-UIFlush
        try {
            $func = $localMap[$key]
            if ($func) { $result = & $func $true; $success++ }
        } catch {
            Write-Log "Erro em $key : $_"
        }
        Set-PopupProgress ($current / $total)
        Invoke-UIFlush
    }

    $PopupTitleText.Text     = "Concluido!"
    $PopupStatusText.Text    = "$success de $total tweaks aplicados"
    $PopupCurrentCmd.Text    = "Todas as operacoes finalizadas"
    $PopupProgressLabel.Text = "$total / $total"
    $StatusText.Text         = "Concluido! $success/$total tweaks aplicados em $catName"
    Set-PopupProgress 1
    Update-Counter
    Update-NavBadges
    Build-OptionsUI $catName
    # Auto-hide popup after 2.5s
    $ht = New-Object System.Windows.Threading.DispatcherTimer
    $ht.Interval = [TimeSpan]::FromMilliseconds(2500)
    $capturedHt = $ht ; $capturedOv = $ProgressOverlay
    $ht.Add_Tick({ $capturedOv.Visibility = "Collapsed"; $capturedHt.Stop() }.GetNewClosure())
    $ht.Start()
})

# ── Helpers de animacao ────────────────────────────────────────────────
function Invoke-FadeIn {
    param($Element, [int]$DurationMs = 400, [scriptblock]$OnComplete = $null)
    $Element.Opacity    = 0
    $Element.Visibility = "Visible"
    $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $anim.From     = 0.0
    $anim.To       = 1.0
    $anim.Duration = [System.Windows.Duration]([TimeSpan]::FromMilliseconds($DurationMs))
    $easing = New-Object System.Windows.Media.Animation.CubicEase
    $easing.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseOut
    $anim.EasingFunction = $easing
    if ($OnComplete) {
        $capturedCb = $OnComplete
        $anim.Add_Completed({ & $capturedCb }.GetNewClosure())
    }
    $Element.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $anim)
}

function Invoke-FadeOut {
    param($Element, [int]$DurationMs = 350, [scriptblock]$OnComplete = $null)
    $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $anim.From     = 1.0
    $anim.To       = 0.0
    $anim.Duration = [System.Windows.Duration]([TimeSpan]::FromMilliseconds($DurationMs))
    $easing = New-Object System.Windows.Media.Animation.CubicEase
    $easing.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseIn
    $anim.EasingFunction = $easing
    $capturedEl = $Element
    if ($OnComplete) { $capturedCb2 = $OnComplete }
    $anim.Add_Completed({
        $capturedEl.Visibility = "Collapsed"
        $capturedEl.Opacity    = 1.0
        if ($capturedCb2) { & $capturedCb2 }
    }.GetNewClosure())
    $Element.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $anim)
}

# ── Funcao: mostrar login com fade-in ──────────────────────────────────
function Show-LoginScreen {
    $capturedLogin  = $LoginOverlay
    $capturedPwBox  = $LoginPasswordBox
    $capturedLoginFb = $LoginFieldBorder
    Invoke-FadeIn $capturedLogin 450 {
        $capturedPwBox.Focus() | Out-Null
    }.GetNewClosure()
}

# ── Funcao: fazer login (valida senha e vai para o app) ────────────────
function Try-Login {
    $capturedLogin    = $LoginOverlay
    $capturedErr      = $LoginErrorText
    $capturedFb       = $LoginFieldBorder
    $capturedPwBox    = $LoginPasswordBox

    $entered = $capturedPwBox.Password
    if ($entered -eq "Yzhy5857") {
        # Senha correta — borda verde rapida
        $capturedFb.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#3FB950")
        $capturedErr.Visibility = "Collapsed"

        # Pequeno delay para o usuario ver o verde, depois fade-out
        $delayTimer = New-Object System.Windows.Threading.DispatcherTimer
        $delayTimer.Interval = [TimeSpan]::FromMilliseconds(400)
        $capturedDt = $delayTimer
        $capturedDt.Add_Tick({
            $capturedDt.Stop()
            Invoke-FadeOut $capturedLogin 500
        }.GetNewClosure())
        $delayTimer.Start()
    } else {
        # Senha errada — borda vermelha + shake
        $capturedFb.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#F85149")
        $capturedErr.Text = "Senha incorreta. Tente novamente."
        $capturedErr.Visibility = "Visible"
        $capturedPwBox.Clear()
        $capturedPwBox.Focus() | Out-Null

        # Animacao de shake horizontal no card
        $shakeTarget = $capturedLogin.Children | Where-Object { $_ -is [System.Windows.Controls.Border] } | Select-Object -Last 1
        if ($shakeTarget) {
            $tt = New-Object System.Windows.Media.TranslateTransform
            $shakeTarget.RenderTransform = $tt
            $shakeAnim = New-Object System.Windows.Media.Animation.DoubleAnimationUsingKeyFrames
            @(0,0; 0.08,-12; 0.16,12; 0.24,-10; 0.32,10; 0.40,-6; 0.48,6; 0.56,0) | ForEach-Object {}
            $frames = @(
                @{T=0;   V=0}
                @{T=0.07;V=-14}
                @{T=0.14;V=14}
                @{T=0.21;V=-10}
                @{T=0.28;V=10}
                @{T=0.35;V=-6}
                @{T=0.42;V=0}
            )
            foreach ($f in $frames) {
                $kf = New-Object System.Windows.Media.Animation.SplineDoubleKeyFrame
                $kf.KeyTime = [System.Windows.Media.Animation.KeyTime]::FromTimeSpan([TimeSpan]::FromSeconds($f.T))
                $kf.Value = $f.V
                $shakeAnim.KeyFrames.Add($kf) | Out-Null
            }
            $shakeAnim.Duration = [System.Windows.Duration]([TimeSpan]::FromMilliseconds(450))
            $tt.BeginAnimation([System.Windows.Media.TranslateTransform]::XProperty, $shakeAnim)
        }

        # Timeout para limpar borda vermelha
        $resetTimer = New-Object System.Windows.Threading.DispatcherTimer
        $resetTimer.Interval = [TimeSpan]::FromMilliseconds(1400)
        $capturedRt = $resetTimer; $capturedFbR = $capturedFb
        $resetTimer.Add_Tick({
            $capturedRt.Stop()
            $capturedFbR.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#30363D")
        }.GetNewClosure())
        $resetTimer.Start()
    }
}

# ── Eventos do login ───────────────────────────────────────────────────
$LoginBtn.Add_Click({ Try-Login })
$LoginPasswordBox.Add_KeyDown({
    if ($_.Key -eq [System.Windows.Input.Key]::Return -or $_.Key -eq [System.Windows.Input.Key]::Enter) {
        Try-Login
    }
})

# ── Splash screen: clickable links ────────────────────────────────────
$SplashWebBtn.Add_MouseLeftButtonUp({ Start-Process "https://varejocode.com.br" })
$SplashDiscordVarejo.Add_MouseLeftButtonUp({ Start-Process "https://discord.gg/gyHSQTNcp6" })
$SplashDiscordYzhy.Add_MouseLeftButtonUp({ Start-Process "https://discord.gg/3eP4txtKNb" })

# ── Splash screen: fade-out after 3.5 s then show LOGIN ─────────────────
$splashTimer = New-Object System.Windows.Threading.DispatcherTimer
$splashTimer.Interval = [TimeSpan]::FromMilliseconds(3500)
$capturedLo = $LoadingOverlay
$capturedSt = $spinTimer
$splashTimer.Add_Tick({
    $this.Stop()
    if ($capturedSt) { $capturedSt.Stop() }   # stop spinner
    # 600 ms smooth fade-out of splash
    $fadeAnim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $fadeAnim.From     = 1.0
    $fadeAnim.To       = 0.0
    $fadeAnim.Duration = [System.Windows.Duration]([TimeSpan]::FromMilliseconds(600))
    $easing = New-Object System.Windows.Media.Animation.CubicEase
    $easing.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseIn
    $fadeAnim.EasingFunction = $easing
    $capturedFadeLo = $capturedLo
    $fadeAnim.Add_Completed({
        $capturedFadeLo.Visibility = "Collapsed"
        $capturedFadeLo.Opacity    = 1.0
        # Show login screen with fade-in
        Show-LoginScreen
    }.GetNewClosure())
    $capturedLo.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fadeAnim)
}.GetNewClosure())
$splashTimer.Start()

# Initial load
Navigate-Category "Sistema"
Update-Counter

# Show window
$Window.ShowDialog() | Out-Null

# Limpa arquivo temporario se executado via loader ($env:TEMP)
if ($MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path -like "$env:TEMP*") {
    Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
}

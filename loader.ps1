# ╔══════════════════════════════════════════════════════════════╗
# ║  YZHY FPS PSW — Loader                                     ║
# ║  Uso:  irm https://seulink.com/loader.ps1 | iex            ║
# ╚══════════════════════════════════════════════════════════════╝

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Configuracao (altere a URL para onde hospedar o script) ───
$scriptUrl = "https://raw.githubusercontent.com/matheusdamoda4-sudo/YzhyFPSREPO/main/YzhyFPS-PSW.ps1"
$tmpFile   = Join-Path $env:TEMP "YzhyFPS-PSW.ps1"

# ── Banner ────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ║   ██    ██ ███████ ██   ██ ██    ██    ███████       ║" -ForegroundColor Cyan
Write-Host "  ║    ██  ██     ███  ██   ██  ██  ██     ██           ║" -ForegroundColor Cyan
Write-Host "  ║     ████     ███   ███████   ████      █████        ║" -ForegroundColor Cyan
Write-Host "  ║      ██     ███    ██   ██    ██       ██           ║" -ForegroundColor Cyan
Write-Host "  ║      ██    ███████ ██   ██    ██       ██           ║" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ║   FPS PSW — Premium Boost • MAX FPS                  ║" -ForegroundColor White
Write-Host "  ║   PowerShell Edition • Build 2026                    ║" -ForegroundColor DarkGray
Write-Host "  ║   Powered by VarejoCode                              ║" -ForegroundColor DarkGray
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Download ──────────────────────────────────────────────────
Write-Host "  [1/3] Baixando YZHY FPS PSW..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $scriptUrl -OutFile $tmpFile -UseBasicParsing -ErrorAction Stop
    Write-Host "  [OK]  Download concluido!" -ForegroundColor Green
} catch {
    Write-Host "  [!!]  Falha ao baixar: $_" -ForegroundColor Red
    Write-Host "  [!!]  Verifique sua conexao com a internet." -ForegroundColor Red
    Write-Host ""
    return
}

# ── Verificacao de admin ──────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── Execucao ──────────────────────────────────────────────────
if ($isAdmin) {
    Write-Host "  [2/3] Executando como Administrador" -ForegroundColor Green
    Write-Host "  [3/3] Iniciando interface grafica..." -ForegroundColor Yellow
    Write-Host ""
    & $tmpFile
} else {
    Write-Host "  [2/3] Solicitando privilegios de Administrador..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$tmpFile`"" -Verb RunAs -ErrorAction Stop
        Write-Host "  [3/3] Janela aberta como Administrador!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  A interface YZHY FPS foi aberta em outra janela." -ForegroundColor DarkGray
        Write-Host "  Voce pode fechar este terminal." -ForegroundColor DarkGray
    } catch {
        Write-Host "  [!!]  UAC negado. Abrindo sem admin..." -ForegroundColor Red
        Write-Host "  [3/3] Iniciando interface grafica..." -ForegroundColor Yellow
        Write-Host ""
        & $tmpFile
    }
}
Write-Host ""

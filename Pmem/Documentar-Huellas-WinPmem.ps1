param(
    [string]$CaseId = "AF-PMEM-2026-VM-WIN-001",
    [string]$Phase = "POST",
    [string]$OutputRoot = "Z:\evidencias",
    [string]$WinPmemPath = "E:\winpmem_mini_x64_rc2.exe"
)

$ErrorActionPreference = "Continue"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path $OutputRoot "$CaseId`_$Phase`_$timestamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Write-Section {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    $safeName = $Name -replace '[\\/:*?"<>| ]', '_'
    $file = Join-Path $outDir "$safeName.txt"

    "===== $Name =====" | Out-File -FilePath $file -Encoding UTF8
    "Fecha/hora local: $(Get-Date -Format o)" | Out-File -FilePath $file -Append -Encoding UTF8
    "" | Out-File -FilePath $file -Append -Encoding UTF8

    try {
        & $Command | Out-File -FilePath $file -Append -Encoding UTF8
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $file -Append -Encoding UTF8
    }
}

Write-Section "00_contexto_sistema" {
    "CaseId: $CaseId"
    "Fase: $Phase"
    "Equipo: $env:COMPUTERNAME"
    "Usuario: $env:USERNAME"
    "Dominio: $env:USERDOMAIN"
    "Fecha/hora: $(Get-Date -Format o)"
    ""
    systeminfo
}

Write-Section "01_identidad_usuario" {
    whoami /all
}

Write-Section "02_hash_herramienta_winpmem" {
    "Ruta declarada de WinPmem: $WinPmemPath"
    if (Test-Path $WinPmemPath) {
        Get-Item $WinPmemPath | Format-List FullName,Length,CreationTime,LastWriteTime,LastAccessTime
        Get-FileHash $WinPmemPath -Algorithm SHA256
    }
    else {
        "No se encontró WinPmem en la ruta indicada."
    }
}

Write-Section "03_unidades_montadas" {
    Get-Volume | Format-Table DriveLetter,FileSystemLabel,FileSystem,DriveType,Size,SizeRemaining -AutoSize
}

Write-Section "04_dispositivos_usb_presentes" {
    Get-PnpDevice -PresentOnly | Where-Object {
        $_.InstanceId -match "USB|USBSTOR" -or $_.FriendlyName -match "USB|Mass Storage|External"
    } | Format-Table Status,Class,FriendlyName,InstanceId -AutoSize
}

Write-Section "05_pagefile" {
    wmic pagefile list brief
}

Write-Section "06_procesos_actuales" {
    Get-Process | Sort-Object ProcessName | Select-Object `
        ProcessName,Id,Path,StartTime -ErrorAction SilentlyContinue | Format-Table -AutoSize
}

Write-Section "07_procesos_tasklist" {
    tasklist /v
}

Write-Section "08_conexiones_red" {
    netstat -ano
}

Write-Section "09_prefetch_relacionado_winpmem" {
    $prefetch = "C:\Windows\Prefetch"
    if (Test-Path $prefetch) {
        Get-ChildItem $prefetch -Filter "*WINPMEM*" -ErrorAction SilentlyContinue |
            Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime |
            Format-Table -AutoSize
    }
    else {
        "Directorio Prefetch no accesible o no existente."
    }
}

Write-Section "10_temporales_relacionados_winpmem" {
    $paths = @($env:TEMP, "C:\Windows\Temp")
    foreach ($p in $paths) {
        "---- $p ----"
        if (Test-Path $p) {
            Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "winpmem|pmem" } |
                Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime |
                Format-Table -AutoSize
        }
    }
}

Write-Section "11_servicios_drivers_relacionados" {
    "Servicios:"
    Get-Service | Where-Object {
        $_.Name -match "pmem|winpmem" -or $_.DisplayName -match "pmem|winpmem"
    } | Format-Table Name,DisplayName,Status,StartType -AutoSize

    ""
    "Drivers en System32\drivers:"
    Get-ChildItem "C:\Windows\System32\drivers" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "pmem|winpmem" } |
        Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime |
        Format-Table -AutoSize
}

Write-Section "12_eventos_servicios_drivers_recientes" {
    $start = (Get-Date).AddHours(-12)
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -match "pmem|winpmem|driver|service|servicio|controlador"
        } |
        Select-Object TimeCreated,Id,ProviderName,Message |
        Format-List
}

Write-Section "13_registro_busqueda_winpmem_servicios" {
    reg query "HKLM\SYSTEM\CurrentControlSet\Services" /f "pmem" /s
}

Write-Section "14_registro_runmru_usuario" {
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
}

Write-Section "15_registro_usb_enum" {
    "USBSTOR:"
    reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s

    ""
    "USB:"
    reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USB" /s
}

Write-Section "16_rutas_recientes_usuario" {
    $recent = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    if (Test-Path $recent) {
        Get-ChildItem $recent -ErrorAction SilentlyContinue |
            Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime |
            Format-Table -AutoSize
    }
}

Write-Section "17_resumen_integridad_salida" {
    "Directorio de salida: $outDir"
    Get-ChildItem $outDir | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize
}

$manifest = Join-Path $outDir "MANIFEST_SHA256.txt"
$manifestTmp = Join-Path $outDir "MANIFEST_SHA256.tmp"

Get-ChildItem $outDir -File |
    Where-Object {
        $_.Name -ne "MANIFEST_SHA256.txt" -and
        $_.Name -ne "MANIFEST_SHA256.tmp"
    } |
    ForEach-Object {
        Get-FileHash $_.FullName -Algorithm SHA256
    } |
    ForEach-Object {
        "$($_.Hash)  $($_.Path)"
    } |
    Out-File -FilePath $manifestTmp -Encoding UTF8

Move-Item -Path $manifestTmp -Destination $manifest -Force

Write-Host "Documentación generada en: $outDir"
Write-Host "Manifiesto SHA256: $manifest"

Write-Host "Documentación generada en: $outDir"
Write-Host "Manifiesto SHA256: $manifest"

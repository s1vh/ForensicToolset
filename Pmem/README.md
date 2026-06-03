# Documentar-Huellas-WinPmem

Script PowerShell para documentar el estado de un sistema Windows antes y después de una adquisición de memoria con WinPmem.

El objetivo es facilitar la trazabilidad del procedimiento, registrar posibles artefactos generados durante la ejecución de la herramienta de adquisición y conservar evidencias auxiliares útiles para un informe forense.

Este script **no borra huellas**, **no limpia artefactos** y **no pretende ocultar la ejecución de herramientas forenses**. Su propósito es documentar.

## Contexto de uso

Durante una adquisición de memoria en vivo, cualquier herramienta ejecutada sobre el sistema objetivo puede modificar el estado del equipo. WinPmem, como otras herramientas de adquisición en caliente, puede dejar rastros asociados a:

- ejecución del binario;
- carga y descarga de controlador;
- archivos temporales;
- Prefetch;
- dispositivos USB conectados;
- rutas recientes;
- eventos del sistema;
- servicios o drivers relacionados;
- conexiones o recursos usados para almacenar evidencias.

Este script permite tomar una fotografía documental **antes** y **después** de la adquisición para comparar el impacto operativo de la herramienta.

## Características

El script recopila información sobre:

- contexto del sistema;
- usuario y privilegios;
- hash SHA-256 local del ejecutable WinPmem usado;
- unidades montadas;
- dispositivos USB presentes;
- configuración de `pagefile.sys`;
- procesos en ejecución;
- conexiones de red;
- posibles entradas Prefetch relacionadas con WinPmem;
- temporales relacionados con `pmem` o `winpmem`;
- servicios y drivers relacionados;
- eventos recientes del sistema;
- claves de Registro relevantes;
- rutas recientes del usuario;
- manifiesto SHA-256 de los archivos generados.

## Requisitos

- Windows 10, Windows 11 o Windows Server compatible.
- PowerShell 5.1 o superior.
- Permisos suficientes para consultar eventos, servicios, Registro y rutas del sistema.
- Ejecución preferiblemente desde una terminal elevada como administrador.
- Un soporte externo o ruta de evidencias con permisos de escritura.

## Estructura recomendada del soporte externo

Ejemplo usando una unidad USB montada como `E:`:

```text
E:\
├── herramientas\
│   ├── winpmem_mini_x64_rc2.exe
│   └── Documentar-Huellas-WinPmem.ps1
└── evidencias\
```

En un entorno pericial real es preferible separar el soporte de herramientas del soporte de evidencias. En un laboratorio académico puede usarse un único soporte si se documenta la limitación.

## Uso básico

Antes de ejecutar el script, puede habilitarse temporalmente la ejecución de scripts para la sesión actual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Captura previa a la adquisición

Ejecutar justo antes de lanzar WinPmem, una vez preparado el escenario que se desea capturar:

```powershell
E:\herramientas\Documentar-Huellas-WinPmem.ps1 `
  -CaseId "AF-PMEM-2026-VM-WIN-001" `
  -Phase "PRE" `
  -OutputRoot "E:\evidencias" `
  -WinPmemPath "E:\herramientas\winpmem_mini_x64_rc2.exe"
```

### Ejecución de WinPmem

Ejemplo con `winpmem_mini_x64_rc2.exe` y método alternativo `-1`:

```cmd
E:\herramientas\winpmem_mini_x64_rc2.exe -1 E:\evidencias\E01_RAM_sigue_al_conejo_blanco.raw > E:\evidencias\winpmem_ejecucion.log 2>&1
```

Después de la adquisición, comprobar tamaño y calcular hash:

```powershell
Get-Item E:\evidencias\E01_RAM_sigue_al_conejo_blanco.raw |
  Format-List FullName,Length,CreationTime,LastWriteTime

Get-FileHash E:\evidencias\E01_RAM_sigue_al_conejo_blanco.raw -Algorithm SHA256 |
  Out-File E:\evidencias\HASH_E01_RAM_SHA256.txt -Encoding UTF8
```

### Captura posterior a la adquisición

Ejecutar después del volcado y del cálculo de hash del RAW:

```powershell
E:\herramientas\Documentar-Huellas-WinPmem.ps1 `
  -CaseId "AF-PMEM-2026-VM-WIN-001" `
  -Phase "POST" `
  -OutputRoot "E:\evidencias" `
  -WinPmemPath "E:\herramientas\winpmem_mini_x64_rc2.exe"
```

## Parámetros

| Parámetro | Descripción | Ejemplo |
|---|---|---|
| `CaseId` | Identificador del caso o laboratorio. | `AF-PMEM-2026-VM-WIN-001` |
| `Phase` | Fase de documentación. Normalmente `PRE` o `POST`. | `PRE` |
| `OutputRoot` | Directorio raíz donde se guardarán los resultados. | `E:\evidencias` |
| `WinPmemPath` | Ruta del ejecutable WinPmem usado en la adquisición. | `E:\herramientas\winpmem_mini_x64_rc2.exe` |

## Salida generada

Por cada ejecución se crea un directorio con esta estructura de nombre:

```text
<CaseId>_<Phase>_<yyyyMMdd_HHmmss>
```

Ejemplo:

```text
AF-PMEM-2026-VM-WIN-001_PRE_20260527_202604
AF-PMEM-2026-VM-WIN-001_POST_20260527_210441
```

Dentro se generan archivos `.txt` con información documental y un manifiesto:

```text
MANIFEST_SHA256.txt
```

El manifiesto contiene hashes SHA-256 de los archivos generados por el script en esa ejecución.

## Flujo de trabajo recomendado

```text
1. Preparar la máquina virtual o sistema objetivo.
2. Conectar el soporte externo de herramientas/evidencias.
3. Preparar el escenario de laboratorio.
4. Ejecutar Documentar-Huellas-WinPmem.ps1 en modo PRE.
5. Ejecutar WinPmem.
6. Verificar tamaño del RAW generado.
7. Calcular SHA-256 del RAW.
8. Ejecutar Documentar-Huellas-WinPmem.ps1 en modo POST.
9. Generar un manifiesto global de evidencias y anexos.
10. Expulsar correctamente el soporte externo.
11. Apagar el sistema auditado si procede.
12. Analizar una copia de trabajo del RAW, no el original.
```

## Manifiesto global de evidencias

Para generar un manifiesto global excluyendo el propio manifiesto:

```powershell
$manifest = "E:\evidencias\MANIFEST_GLOBAL_SHA256.txt"
$tmp = "E:\evidencias\MANIFEST_GLOBAL_SHA256.tmp"

Get-ChildItem E:\evidencias -Recurse -File |
    Where-Object {
        $_.FullName -ne $manifest -and
        $_.FullName -ne $tmp -and
        $_.Name -ne "HASH_MANIFEST_GLOBAL_SHA256.txt"
    } |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object {
        "$($_.Hash)  $($_.Path)"
    } |
    Out-File $tmp -Encoding UTF8

Move-Item $tmp $manifest -Force
```

Después puede calcularse el hash del propio manifiesto:

```powershell
Get-FileHash E:\evidencias\MANIFEST_GLOBAL_SHA256.txt -Algorithm SHA256 |
  Out-File E:\evidencias\HASH_MANIFEST_GLOBAL_SHA256.txt -Encoding UTF8
```

## Consideraciones forenses

Este script está pensado para apoyar la documentación del procedimiento, no para sustituir la metodología forense.

Recomendaciones:

- Registrar fecha, hora, usuario, equipo y comandos ejecutados.
- Calcular hash del binario de adquisición usado, aunque no exista hash oficial publicado.
- Calcular hash del RAW inmediatamente después de la adquisición.
- Conservar logs de ejecución de WinPmem.
- No trabajar directamente sobre el RAW original.
- Crear una copia de trabajo y verificar que su hash coincide.
- Documentar cualquier intento fallido, especialmente si genera archivos de 0 bytes.
- No eliminar artefactos del sistema auditado salvo que exista autorización expresa, justificación técnica y documentación completa.

## Limitaciones

- La ejecución del propio script modifica mínimamente el sistema, como cualquier ejecución en vivo.
- Algunas consultas pueden requerir privilegios de administrador.
- Algunas rutas, eventos o claves de Registro pueden no existir en todos los sistemas.
- La salida depende de la versión de Windows, configuración de auditoría, política de ejecución y permisos.
- El script no valida la autenticidad de WinPmem; solo calcula un hash local del binario indicado.
- El script no garantiza admisibilidad probatoria por sí mismo.

## Tratamiento de intentos fallidos

Si WinPmem genera un archivo RAW vacío, puede identificarse por:

- tamaño `0 bytes`;
- hash SHA-256 de archivo vacío:

```text
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
```

En ese caso se recomienda:

1. renombrar el archivo como intento fallido;
2. conservar el log de ejecución;
3. documentar la incidencia;
4. repetir la adquisición corrigiendo la causa o usando otro método de adquisición;
5. no tratar el archivo vacío como evidencia de memoria.

Ejemplo:

```powershell
Rename-Item `
  E:\evidencias\E01_RAM_sigue_al_conejo_blanco.raw `
  E:\evidencias\E01_RAM_sigue_al_conejo_blanco_INTENTO01_FALLIDO_0_BYTES.raw
```

## Ejemplo de redacción para informe

```text
Se realizó una toma documental previa y posterior a la adquisición de memoria
con el objetivo de identificar el impacto operativo de la herramienta WinPmem
sobre el sistema auditado.

No se eliminaron artefactos generados por la ejecución de las herramientas, al
considerarse parte del contexto técnico de la adquisición. La reutilización del
entorno de laboratorio se realizó mediante restauración o eliminación de la
máquina virtual, fuera del flujo de custodia de la evidencia.
```

## Buenas prácticas de seguridad

- Usar una máquina virtual limpia para laboratorios académicos.
- No adquirir memoria de equipos personales si el volcado va a compartirse.
- No incluir credenciales reales, sesiones personales ni información sensible.
- Evitar acceder a servicios reales innecesarios durante el escenario.
- Mantener separadas, cuando sea posible, herramientas y evidencias.
- Usar soportes externos controlados.
- Expulsar correctamente los soportes antes de apagar o desconectar.

## Aviso legal y ético

Este proyecto tiene finalidad educativa y de apoyo a prácticas de análisis forense digital.

No debe utilizarse para ocultar actividad, destruir evidencias, evadir investigaciones ni alterar sistemas de terceros. Cualquier uso en entornos reales debe contar con autorización expresa y ajustarse a la legislación aplicable, políticas internas y procedimientos de cadena de custodia correspondientes.

## Licencia

Publicado bajo licencia MIT.


<#
.SYNOPSIS
  Dumps live stack traces from a hung vuln-hunter MCP server process using py-spy.

.DESCRIPTION
  vuln-hunter's own faulthandler-based watchdog (_stall_watchdog in mcp_server.py)
  only covers code running inside the with-block it wraps -- it can't catch a
  hang in a phase it never got to. When a vuln-hunter tool call goes silent
  with no diagnostic output at all, this script attaches to the *external*
  process with py-spy (github.com/benfred/py-spy) to see exactly where every
  thread is stuck, without needing anything inside vuln-hunter itself to be
  responsive.

  Deliberately NOT an MCP tool on vuln-hunter's own server: if vuln-hunter's
  process is the thing that's frozen, it can't answer any tool call at all,
  including a self-diagnostic one hosted on the same server. This has to run
  from outside.

.NOTES
  Requires an elevated (Administrator) PowerShell session -- py-spy needs to
  read another process's memory, which Windows only allows for admins.
  Install: python -m pip install --user py-spy
#>

$ErrorActionPreference = "Stop"

$pySpy = Get-Command py-spy -ErrorAction SilentlyContinue
if (-not $pySpy) {
    $userScripts = Join-Path ([Environment]::GetFolderPath("ApplicationData")) "Python\Python314\Scripts\py-spy.exe"
    if (Test-Path $userScripts) {
        $pySpy = $userScripts
    } else {
        Write-Error "py-spy not found on PATH or at $userScripts. Install: python -m pip install --user py-spy"
        exit 1
    }
} else {
    $pySpy = $pySpy.Source
}

$procs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Where-Object { $_.CommandLine -like "*mcp_server.py*" }

if (-not $procs) {
    Write-Host "No running vuln-hunter mcp_server.py process found."
    Write-Host "(Checked: python.exe processes with 'mcp_server.py' in their command line.)"
    exit 0
}

foreach ($proc in $procs) {
    $startTime = $proc.CreationDate
    Write-Host "=== PID $($proc.ProcessId) -- started $startTime ==="
    Write-Host "Command line: $($proc.CommandLine)"
    Write-Host ""

    # py-spy dump: attaches, reads stack of every thread, detaches. Does not
    # pause the target process for more than the brief read (safe on a live
    # server, doesn't kill or restart anything).
    & $pySpy dump --pid $proc.ProcessId
    Write-Host ""
}

# Downloads Chart.js once so the dashboard charts work fully offline.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File scripts\get_chartjs.ps1
$dest = "frontend\js\vendor\chart.umd.min.js"
Invoke-WebRequest -Uri "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" -OutFile $dest
Write-Host "Saved $dest"

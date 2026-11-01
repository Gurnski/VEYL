# Renders the VEYL mark into assets\veyl.ico (16-256 px, PNG-compressed entries).
# Run once, or again after changing the mark. Matches LogoGeometry in Theme.xaml.
Add-Type -AssemblyName System.Drawing

$out = Join-Path $PSScriptRoot '..\assets\veyl.ico'
$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = @()

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Rounded dark tile
    $r = [Math]::Max(3, $s * 0.22)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($s - $d - 1, 0, $d, $d, 270, 90)
    $path.AddArc($s - $d - 1, $s - $d - 1, $d, $d, 0, 90)
    $path.AddArc(0, $s - $d - 1, $d, $d, 90, 90)
    $path.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0x1E, 0x1A, 0x25))), $path)

    # Mark, drawn in a 24-unit box scaled to the tile
    $k = $s / 24.0
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 0xEB, 0xA6, 0x40)), ([Math]::Max(1.2, 2.0 * $k))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    function P($x, $y) { New-Object System.Drawing.PointF ([float]($x * $k)), ([float]($y * $k)) }
    $g.DrawLines($pen, [System.Drawing.PointF[]]@((P 4 5.5), (P 12 20), (P 20 5.5)))
    $g.DrawBezier($pen, (P 7 5.5), (P 9.2 8.8), (P 14.8 8.8), (P 17 5.5))
    if ($s -ge 32) { $g.DrawBezier($pen, (P 9.8 11.4), (P 11.2 12.4), (P 12.8 12.4), (P 14.2 11.4)) }

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $pngs += , $ms.ToArray()
}

$fs = [System.IO.File]::Create($out)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$pngs[$i].Length); $w.Write([UInt32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
$w.Close()
Write-Host "Wrote $out"

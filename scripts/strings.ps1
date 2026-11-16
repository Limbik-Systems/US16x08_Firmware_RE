param([string]$f, [string]$pattern = ".", [int]$min = 5)
$b = [IO.File]::ReadAllBytes($f)
$rx = [regex]::new($pattern, 'IgnoreCase')
$sb = New-Object Text.StringBuilder
$start = 0
for ($i = 0; $i -lt $b.Length; $i++) {
    $c = $b[$i]
    if ($c -ge 0x20 -and $c -lt 0x7F) {
        if ($sb.Length -eq 0) { $start = $i }
        [void]$sb.Append([char]$c)
    } else {
        if ($sb.Length -ge $min) {
            $s = $sb.ToString()
            if ($rx.IsMatch($s)) { "{0:X8}  {1}" -f $start, $s }
        }
        [void]$sb.Clear()
    }
}

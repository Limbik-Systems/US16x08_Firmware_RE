param([string]$f)
$b = [IO.File]::ReadAllBytes($f)
$pe = [BitConverter]::ToInt32($b, 0x3C)
"PE sig: {0:X8}" -f [BitConverter]::ToUInt32($b, $pe)
"machine: 0x{0:X4}" -f [BitConverter]::ToUInt16($b, $pe + 4)
$n = [BitConverter]::ToUInt16($b, $pe + 6)
$opt = [BitConverter]::ToUInt16($b, $pe + 20)
$st = $pe + 24 + $opt
"sections: $n"
for ($i = 0; $i -lt $n; $i++) {
    $h = $st + $i * 40
    $name = [Text.Encoding]::ASCII.GetString($b, $h, 8).TrimEnd([char]0)
    $vsize = [BitConverter]::ToUInt32($b, $h + 8)
    $raw = [BitConverter]::ToInt32($b, $h + 20)
    $rsize = [BitConverter]::ToInt32($b, $h + 16)
    "{0,-10} vsize={1,8:X} rawptr={2,8:X} rawsize={3,8:X}" -f $name, $vsize, $raw, $rsize
}

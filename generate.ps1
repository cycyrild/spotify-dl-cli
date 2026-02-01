$Protoc = "C:\Users\admin\Downloads\protoc\bin\protoc"
$Include2 = "C:\Users\admin\Downloads\protoc\include"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ProtoDir = Join-Path $ScriptDir "proto"

$OutDir = $ProtoDir

$ProtoFiles = @(
    "track.proto",
    "storage-resolve.proto",
    "playplay.proto"
)

foreach ($Proto in $ProtoFiles) {
    & $Protoc `
      -I $ProtoDir `
      -I $Include2 `
      --python_out=$OutDir `
      --pyi_out=$OutDir `
      (Join-Path $ProtoDir $Proto)
}

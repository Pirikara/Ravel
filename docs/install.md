# Install Ravel

The current beta is `v0.1.0-beta.1`. Download its binaries and `SHA256SUMS` from the [GitHub release](https://github.com/Pirikara/Ravel/releases/tag/v0.1.0-beta.1).

| Platform | Target |
| --- | --- |
| macOS Apple silicon | `darwin_arm64` |
| macOS Intel | `darwin_amd64` |
| Linux x86-64 | `linux_amd64` |
| Linux ARM64 | `linux_arm64` |
| Windows x86-64 | `windows_amd64` |

## macOS and Linux

Set `target` to the value for your machine from the table. This example uses macOS Apple silicon:

```sh
version=v0.1.0-beta.1
target=darwin_arm64
archive="ravel_${version}_${target}.tar.gz"
base="https://github.com/Pirikara/Ravel/releases/download/${version}"

curl -fLO "${base}/${archive}"
curl -fLO "${base}/SHA256SUMS"
entry=$(awk -v name="$archive" '$2 == name { print }' SHA256SUMS)
test -n "$entry"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s\n' "$entry" | sha256sum -c -
else
  printf '%s\n' "$entry" | shasum -a 256 -c -
fi

tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 755 "ravel_${version}_${target}/ravel" "$HOME/.local/bin/ravel"
export PATH="$HOME/.local/bin:$PATH"
ravel version
```

Add `$HOME/.local/bin` to your shell's `PATH` configuration to keep the command available in future sessions. The archive also contains the license and third-party notices.

## Windows

In PowerShell, download and verify the Windows archive:

```powershell
$version = 'v0.1.0-beta.1'
$archive = "ravel_${version}_windows_amd64.zip"
$base = "https://github.com/Pirikara/Ravel/releases/download/$version"

Invoke-WebRequest "$base/$archive" -OutFile $archive
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
$entry = Get-Content SHA256SUMS | Where-Object { $_.EndsWith("  $archive") }
if (@($entry).Count -ne 1) { throw 'Checksum entry missing or ambiguous' }
$expected = ($entry -split '\s+')[0]
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ine $expected) {
    throw 'Checksum mismatch'
}

Expand-Archive $archive -DestinationPath .
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
Copy-Item "ravel_${version}_windows_amd64\ravel.exe" "$env:USERPROFILE\bin\ravel.exe"
$env:PATH = "$env:USERPROFILE\bin;$env:PATH"
ravel version
```

Add `%USERPROFILE%\bin` to your user `Path` environment variable to keep the command available in future sessions.

## Install with Go

With Go 1.27 or newer:

```sh
go install github.com/Pirikara/Ravel/cmd/ravel@v0.1.0-beta.1
```

The binary is installed in `GOBIN`, or in `GOPATH/bin` when `GOBIN` is unset. Make sure that directory is on your `PATH`.

## Build from source

```sh
git clone https://github.com/Pirikara/Ravel.git
cd Ravel
go build -o ravel ./cmd/ravel
./ravel version
```

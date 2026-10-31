package oci

import (
	"bytes"

	"ravel/internal/model"
)

const phpFPMBinaryPath = "usr/local/sbin/php-fpm"

type phpFPMBinaryState struct {
	document model.Document
	status   string
}

func inspectPHPFPMBinary(data []byte, source, project, architecture string) (model.Document, error) {
	return inspectPHPBinary(data, source, project, architecture, "php-fpm", phpFPMBinaryPath, phpFPMVersionInROData)
}

// The FPM executable shares the PHP and Zend Engine version evidence with
// the CLI executable but has its own FastCGI identity and output banner.
func phpFPMVersionInROData(data []byte) (string, int, bool) {
	if !bytes.Contains(data, []byte("\x00fpm-fcgi\x00")) ||
		!bytes.Contains(data, []byte("\x00FastCGI Process Manager\x00")) ||
		!bytes.Contains(data, []byte("\x00PHP %s (%s) (built: %s %s)")) ||
		!bytes.Contains(data, []byte("\nCopyright (c) The PHP Group\n")) {
		return "", -1, false
	}
	return php8VersionInROData(data)
}

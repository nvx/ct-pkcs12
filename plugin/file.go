package plugin

import (
	"bytes"
	"github.com/natefinch/atomic"
)

func WriteFile(fileName string, p12 []byte) error {
	return atomic.WriteFile(fileName, bytes.NewBuffer(p12))
}

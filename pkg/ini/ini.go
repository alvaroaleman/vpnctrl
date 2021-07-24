package ini

import (
	"bytes"
	"fmt"

	"gopkg.in/ini.v1"
)

func Marshal(in interface{}) ([]byte, error) {
	if f, x := in.(interface{ MarshalIni() ([]byte, error) }); x {
		return f.MarshalIni()
	}
	file := ini.Empty()
	if err := ini.ReflectFrom(file, in); err != nil {
		return nil, fmt.Errorf("reflectFrom: %w", err)
	}
	var buf bytes.Buffer
	if _, err := file.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize: %w", err)
	}
	return buf.Bytes(), nil

}

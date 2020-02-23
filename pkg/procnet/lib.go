package procnet

import (
	"fmt"

	"github.com/prometheus/procfs"
)

func Get() error {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return err
	}
	fmt.Println(fs.NetSockstat())
	return nil
}

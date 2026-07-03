package filesystem

import (
	"io/fs"
	"syscall"
	"time"
)

func buildTimes(info fs.FileInfo, _ string) (Times, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Times{}, syscall.EINVAL
	}
	return Times{
		Creation:     time.Unix(stat.Birthtimespec.Unix()),
		Modification: info.ModTime(),
		Access:       time.Unix(stat.Atimespec.Unix()),
		Change:       time.Unix(stat.Ctimespec.Unix()),
	}, nil
}

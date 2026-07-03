package filesystem

import (
	"io/fs"
	"syscall"
	"time"
)

func buildTimes(info fs.FileInfo, _ string) (Times, error) {
	stat, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return Times{}, syscall.EINVAL
	}
	return Times{
		Creation:     filetimeToTime(stat.CreationTime),
		Modification: info.ModTime(),
		Access:       filetimeToTime(stat.LastAccessTime),
		Change:       time.Time{},
	}, nil
}

func filetimeToTime(filetime syscall.Filetime) time.Time {
	return time.Unix(0, filetime.Nanoseconds())
}

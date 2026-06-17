package filesystem

import (
	"io/fs"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newTimes(info fs.FileInfo, path string) (Times, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Times{}, syscall.EINVAL
	}

	creationTime, _ := birthTime(path)
	return Times{
		Creation:     creationTime,
		Modification: info.ModTime(),
		Access:       time.Unix(stat.Atim.Unix()),
		Change:       time.Unix(stat.Ctim.Unix()),
	}, nil
}

func birthTime(path string) (time.Time, error) {
	var stat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &stat); err != nil {
		return time.Time{}, err
	}
	if stat.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, ErrNoBirthTime
	}
	return time.Unix(stat.Btime.Sec, int64(stat.Btime.Nsec)), nil
}

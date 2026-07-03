package filesystem

import (
	"io/fs"
	"time"
)

type Times struct {
	Creation     time.Time
	Modification time.Time
	Access       time.Time
	Change       time.Time
}

func NewTimes(info fs.FileInfo, path string) (Times, error) {
	return buildTimes(info, path)
}

//go:build !windows

package audit

import "golang.org/x/sys/unix"

// diskUsagePercent returns the used percentage of the volume that contains path.
func diskUsagePercent(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Blocks == 0 {
		return 0, nil
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	return int64((total - free) * 100 / total), nil
}

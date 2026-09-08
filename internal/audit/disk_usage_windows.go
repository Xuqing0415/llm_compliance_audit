//go:build windows

package audit

import "golang.org/x/sys/windows"

// diskUsagePercent returns the used percentage of the volume that contains path.
func diskUsagePercent(path string) (int64, error) {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var free, total, avail uint64
	if err := windows.GetDiskFreeSpaceEx(pathp, &free, &total, &avail); err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}
	return int64((total - free) * 100 / total), nil
}

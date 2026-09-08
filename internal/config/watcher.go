package config

import (
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

type FileWatcher struct {
	watcher *fsnotify.Watcher
	done    chan bool
}

func NewFileWatcher() (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &FileWatcher{
		watcher: watcher,
		done:    make(chan bool),
	}, nil
}

func (fw *FileWatcher) Watch(path string, callback func()) error {
	if err := fw.watcher.Add(path); err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		var lastEventTime time.Time

		for {
			select {
			case event, ok := <-fw.watcher.Events:
				if !ok {
					return
				}

				relevant := event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
					event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)
				if !relevant {
					continue
				}

				now := time.Now()
				if now.Sub(lastEventTime) <= time.Second {
					// Coalesce the burst of events editors produce on save.
					continue
				}
				lastEventTime = now

				// Editors that save via write-temp + rename (vim, many IDEs)
				// replace the watched inode; re-establish the watch so hot
				// reload keeps working afterwards.
				if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
					time.AfterFunc(200*time.Millisecond, func() {
						if err := fw.watcher.Add(path); err != nil {
							logrus.Warn("Failed to re-add file to watcher:", path, err)
						}
					})
				}

				logrus.Info("Config file changed, triggering reload...")
				callback()
			case err, ok := <-fw.watcher.Errors:
				if !ok {
					return
				}
				logrus.Error("Watcher error:", err)
			case <-fw.done:
				return
			}
		}
	}()

	return nil
}

func (fw *FileWatcher) Close() error {
	close(fw.done)
	return fw.watcher.Close()
}

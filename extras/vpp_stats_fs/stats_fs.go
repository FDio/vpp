/*
 * Copyright (c) 2021 Cisco Systems and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*Go-FUSE allows us to define the behaviour of our filesystem by recoding any primitive function we need.
 *The structure of the filesystem is constructed as a tree.
 *Each type of nodes (root, directory, file) follows its own prmitives.
 */
package main

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/statsclient"
)

func updateDir(ctx context.Context, n *fs.Inode, cl *statsclient.StatsClient, dirPath string) syscall.Errno {
	stats, err := cl.PrepareDir(dirPath)
	if err != nil {
		logger.Printf(fmt.Sprintf("Listing stats index failed: %v\n", err))
		return syscall.EAGAIN
	}

	n.Operations().(*dirNode).epoch = stats.Epoch

	n.RmAllChildren()

	for _, entry := range stats.Entries {
		localPath := strings.TrimPrefix(string(entry.Name), dirPath)
		dirPath, base := filepath.Split(localPath)

		parent := n
		for _, component := range strings.Split(dirPath, "/") {
			if len(component) == 0 {
				continue
			}
			child := parent.GetChild(component)
			if child == nil {
				child = parent.NewInode(ctx, &dirNode{client: cl, epoch: stats.Epoch},
					fs.StableAttr{Mode: fuse.S_IFDIR})
				parent.AddChild(component, child, true)
			} else {
				child.Operations().(*dirNode).epoch = stats.Epoch
			}

			parent = child
		}

		filename := strings.Replace(base, " ", "_", -1)
		child := parent.GetChild(filename)
		if child == nil {
			child := parent.NewPersistentInode(ctx, &statNode{client: cl, index: entry.Index}, fs.StableAttr{})
			parent.AddChild(filename, child, true)
		}
	}
	return 0
}

func getCounterContent(index uint32, client *statsclient.StatsClient) (content string, status syscall.Errno) {
	content = ""
	statsDir, err := client.PrepareDirOnIndex(index)
	if err != nil {
		logger.Printf(fmt.Sprintf("Dumping stats on index failed: %v\n", err))
		return content, syscall.EAGAIN
	}
	if len(statsDir.Entries) != 1 {
		return content, syscall.ENOENT
	}
	result := statsDir.Entries[0]
	if result.Data == nil {
		return content, 0
	}

	switch result.Type {
	case adapter.ScalarIndex:
		stats := result.Data.(adapter.ScalarStat)
		content = fmt.Sprintf("%.2f\n", stats)
	case adapter.ErrorIndex:
		stats := result.Data.(adapter.ErrorStat)
		content = fmt.Sprintf("%-16s%s\n", "Index", "Count")
		for i, value := range stats {
			content += fmt.Sprintf("%-16d%d\n", i, value)
		}
	case adapter.SimpleCounterVector:
		stats := result.Data.(adapter.SimpleCounterStat)
		content = fmt.Sprintf("%-16s%-16s%s\n", "Thread", "Index", "Packets")
		for i, vector := range stats {
			for j, value := range vector {
				content += fmt.Sprintf("%-16d%-16d%d\n", i, j, value)
			}
		}
	case adapter.CombinedCounterVector:
		stats := result.Data.(adapter.CombinedCounterStat)
		content = fmt.Sprintf("%-16s%-16s%-16s%s\n", "Thread", "Index", "Packets", "Bytes")
		for i, vector := range stats {
			for j, value := range vector {
				content += fmt.Sprintf("%-16d%-16d%-16d%d\n", i, j, value[0], value[1])
			}
		}
	case adapter.NameVector:
		stats := result.Data.(adapter.NameStat)
		content = fmt.Sprintf("%-16s%s\n", "Index", "Name")
		for i, value := range stats {
			content += fmt.Sprintf("%-16d%s\n", i, string(value))
		}
	default:
		content = fmt.Sprintf("Unknown stat type: %d\n", result.Type)
		//For now, the empty type (file deleted) is not implemented in GoVPP
		return content, syscall.ENOENT
	}
	return content, fs.OK
}

//The dirNode structure represents directories
type dirNode struct {
	fs.Inode
	client *statsclient.StatsClient
	epoch  int64
}

var _ = (fs.NodeOpendirer)((*dirNode)(nil))
var _ = (fs.NodeGetattrer)((*dirNode)(nil))
var _ = (fs.NodeOnAdder)((*dirNode)(nil))

func (dn *dirNode) OnAdd(ctx context.Context) {
	if dn.Inode.IsRoot() {
		updateDir(ctx, &dn.Inode, dn.client, "/")
	}
}

func (dn *dirNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mtime = uint64(time.Now().Unix())
	out.Atime = out.Mtime
	out.Ctime = out.Mtime
	return 0
}

func (dn *dirNode) Opendir(ctx context.Context) syscall.Errno {
	var status syscall.Errno = syscall.F_OK
	var sleepTime time.Duration = 10 * time.Millisecond
	newEpoch, inProgress := dn.client.GetEpoch()
	for inProgress {
		newEpoch, inProgress = dn.client.GetEpoch()
		time.Sleep(sleepTime)
		sleepTime = sleepTime * 2
	}

	//We check that the directory epoch is up to date
	if dn.epoch != newEpoch {
		//directoryPath is the path to the current directory from root
		directoryPath := path.Clean("/" + dn.Inode.Path(nil) + "/")
		status = updateDir(ctx, &dn.Inode, dn.client, directoryPath)
	}
	return status
}

//The statNode structure represents counters
type statNode struct {
	fs.Inode
	client *statsclient.StatsClient
	index  uint32
}

var _ = (fs.NodeOpener)((*statNode)(nil))
var _ = (fs.NodeGetattrer)((*statNode)(nil))

func (fh *statNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mtime = uint64(time.Now().Unix())
	out.Atime = out.Mtime
	out.Ctime = out.Mtime
	return 0
}

//When a file is opened, the correpsonding counter value is dumped and a file handle is created
func (sn *statNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	content, status := getCounterContent(sn.index, sn.client)
	if status == syscall.ENOENT {
		_, parent := sn.Inode.Parent()
		parent.RmChild(sn.Inode.Path(parent))

	}
	return &statFH{data: []byte(content)}, fuse.FOPEN_DIRECT_IO, status
}

/* The statFH structure aims at dislaying the counters dynamically.
 * It allows the Kernel to read data as I/O without having to specify files sizes, as they may evolve dynamically.
 */
type statFH struct {
	data []byte
}

var _ = (fs.FileReader)((*statFH)(nil))

func (fh *statFH) Read(ctx context.Context, data []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := int(off) + len(data)
	if end > len(fh.data) {
		end = len(fh.data)
	}
	return fuse.ReadResultData(fh.data[off:end]), fs.OK
}

//NewStatsFileSystem creates the fs for the stat segment.
func NewStatsFileSystem(sc *statsclient.StatsClient) (root fs.InodeEmbedder, err error) {
	return &dirNode{client: sc}, nil
}

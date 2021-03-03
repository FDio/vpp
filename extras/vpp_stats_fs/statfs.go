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

/*
 * Go-FUSE allows us to define the behaviour of our filesystem by recoding any primitive function we need.
 * The structure of the filesystem is constructed as a tree.
 * Each type of nodes (root, directory, file) follows its own prmitives.
 */
package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/statsclient"
)

func updateDir(ctx context.Context, n *fs.Inode, cl *statsclient.StatsClient, epoch int64) syscall.Errno {
	dirStats, err := cl.PrepareDir("/")
	if err != nil {
		log.Println("list stats failed:", err)
		return syscall.EAGAIN
	}

	if dirStats == nil {
		log.Println("Error accessing the directory vector of the stat segment.")
		return syscall.EAGAIN
	}

	if len(dirStats.Indexes) == 0 {
		n.ForgetPersistent()
		return syscall.ENOENT
	}

	for i, index := range dirStats.Indexes {
		path := string(dirStats.Entries[i].Name)
		dir, base := filepath.Split(path)

		parent := n
		for _, component := range strings.Split(dir, "/") {
			if len(component) == 0 {
				continue
			}
			child := parent.GetChild(component)
			if child == nil {
				child = parent.NewInode(ctx, &dirNode{client: cl},
					fs.StableAttr{Mode: fuse.S_IFDIR})
				parent.AddChild(component, child, true)
			}
			parent = child
		}
		child := parent.GetChild(base)
		if child == nil {
			child := parent.NewPersistentInode(ctx, &statNode{client: cl, path: path, index: index, name: base}, fs.StableAttr{})
			parent.AddChild(base, child, true)
		}
	}
	return 0
}

type vecHeader struct {
	length     uint64
	vectorData [0]uint8
}

func vectorLen(v unsafe.Pointer) unsafe.Pointer {
	vec := *(*vecHeader)(unsafe.Pointer(uintptr(v) - unsafe.Sizeof(uint64(0))))
	return unsafe.Pointer(&vec.length)
}

func getCounterContent(index uint32, client *statsclient.StatsClient) (content string, status syscall.Errno) {

	content = ""

	/*Issue: I can use function GetStatDirOnIndex but I need accessStart/accessEnd
	which are not available outside of the scope of the statclient package*/
	dirVector := client.GetDirectoryVector()
	if dirVector == nil {
		log.Println("Error accessing the directory vector of the stat segment.")
		return content, syscall.EAGAIN
	}
	dirLen := *(*uint32)(vectorLen(dirVector))

	if index >= dirLen {
		return content, syscall.ENOENT
	}

	dirPtr, dirName, dirType := client.GetStatDirOnIndex(dirVector, index)
	entry := adapter.StatEntry{
		Name: append([]byte(nil), dirName...),
		Type: adapter.StatType(dirType),
		Data: client.CopyEntryData(dirPtr),
	}

	if entry.Data == nil {
		return content, 0
	}
	switch entry.Type {
	case adapter.ScalarIndex:
		stats := entry.Data.(adapter.ScalarStat)
		content = fmt.Sprintf("%.2f\n", stats)
	case adapter.ErrorIndex:
		stats := entry.Data.(adapter.ErrorStat)
		content = fmt.Sprintf("%-16s%s\n", "Index", "Count")
		content += fmt.Sprintf("%-16d%d\n", 0, stats)
	case adapter.SimpleCounterVector:
		stats := entry.Data.(adapter.SimpleCounterStat)
		content = fmt.Sprintf("%-16s%-16s%s\n", "Index1", "Index2", "Packets")
		for i, vector := range stats {
			for j, value := range vector {
				content += fmt.Sprintf("%-16d%-16d%d\n", i, j, value)
			}
		}
	case adapter.CombinedCounterVector:
		stats := entry.Data.(adapter.CombinedCounterStat)
		content = fmt.Sprintf("%-16s%-16s%-16s%s\n", "Index1", "Index2", "Packets", "Bytes")
		for i, vector := range stats {
			for j, value := range vector {
				content += fmt.Sprintf("%-16d%-16d%-16d%d\n", i, j, value[0], value[1])
			}
		}
	case adapter.NameVector:
		stats := entry.Data.(adapter.NameStat)
		content = fmt.Sprintf("%-16s%s\n", "Index", "Name")
		for i, value := range stats {
			content += fmt.Sprintf("%-16d%s\n", i, string(value))
		}
	default:
		content = fmt.Sprintf("Unknown stat type: %d\n", entry.Type)
		//For now, the empty type (file deleted) is not implemented in GoVPP
		return content, syscall.ENOENT
	}
	return content, fs.OK
}

type rootNode struct {
	fs.Inode
	client *statsclient.StatsClient
	epoch  int64
}

var _ = (fs.NodeOnAdder)((*rootNode)(nil))

func (root *rootNode) OnAdd(ctx context.Context) {
	epoch, inProgress := root.client.GetEpoch()
	for inProgress {
		epoch, inProgress = root.client.GetEpoch()
	}
	updateDir(ctx, &root.Inode, root.client, epoch)
	root.epoch = epoch
}

//The dirNode structure represents directories
type dirNode struct {
	fs.Inode
	client *statsclient.StatsClient
}

var _ = (fs.NodeOpendirer)((*dirNode)(nil))

func (dn *dirNode) Opendir(ctx context.Context) syscall.Errno {
	epoch, inProgress := dn.client.GetEpoch()
	for inProgress {
		epoch, inProgress = dn.client.GetEpoch()
	}

	//Get the root node
	root := dn.Root().Operations().(*rootNode)

	//We do not update a directory if epoch has not changed
	if epoch == root.epoch {
		return 0
	}

	status := updateDir(ctx, &root.Inode, dn.client, epoch)
	root.epoch = epoch

	return status
}

//The statNode structure represents counters
type statNode struct {
	fs.Inode
	client *statsclient.StatsClient
	path   string
	index  uint32
	name   string
}

var _ = (fs.NodeOpener)((*statNode)(nil))

//When a file is opened, the correpsonding counter value is dumped and a file handle is created
func (sn *statNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	content, status := getCounterContent(sn.index, sn.client)
	if status == syscall.ENOENT {
		sn.Inode.ForgetPersistent()
		_, parent := sn.Parent()
		parent.RmChild(sn.name)
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
	return &rootNode{client: sc}, nil
}

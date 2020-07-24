package main

import (
	"context"
	"fmt"
	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/binapi/fib_types"
	"git.fd.io/govpp.git/binapi/ip"
	"git.fd.io/govpp.git/binapi/ip_types"
	"git.fd.io/govpp.git/binapi/tracedump"
	"git.fd.io/govpp.git/binapi/vpe"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

func tracedump_test() {
	var stream api.Stream
	var err error

	// Connect to VPP
	conn, err := govpp.Connect("/run/vpp/api.sock")

	if err != nil {
		fmt.Printf("Connect: %s\n", err.Error())
		return
	}

	defer conn.Disconnect()

	// Open channel
	ch, _ := conn.NewAPIChannel()
	defer ch.Close()

	// Prepare messages
	req := &vpe.ShowVersion{}
	reply := &vpe.ShowVersionReply{}

	// Send the request
	err = ch.SendRequest(req).ReceiveReply(reply)

	if err != nil {
		fmt.Printf("SendRequest: %s\n", err.Error())
		return
	}

	fmt.Printf("Program: %s\nVersion: %s\nBuildDate: %s\n",
		reply.Program, reply.Version, reply.BuildDate)

	dump_msg := &tracedump.TraceDump{ClearCache: 1,
		ThreadID:   0,
		Position:   0,
		MaxRecords: 10}

	var need_close bool = false

	for {
		ctx := context.Background()
		stream, err = conn.NewStream(ctx)
		if err != nil {
			panic(err)
		}

		need_close = true

		err = stream.SendMsg(dump_msg)
		if err != nil {
			fmt.Printf("RecvMsg failed: %s\n", err.Error())
			goto doublebreak
		}

		for {
			msg, err := stream.RecvMsg()
			if err != nil {
				fmt.Printf("RecvMsg failed: %s\n", err.Error())
				goto doublebreak
			}

			switch msg.(type) {
			case *tracedump.TraceDumpReply:
				reply_msg, _ := msg.(*tracedump.TraceDumpReply)
				if reply_msg.Retval != 0 {
					fmt.Printf("Error return %d:\n", reply_msg.Retval)
					goto doublebreak
				} else {
					fmt.Printf("OK reply, done %d...\n",
						reply_msg.Done)
				}
				dump_msg.ThreadID = reply_msg.LastThreadID
				dump_msg.Position = reply_msg.LastPosition
				if reply_msg.MoreThreads != 0 {
					dump_msg.Position = 0
					dump_msg.ThreadID++
				} else {
					dump_msg.Position++
				}
				if reply_msg.Done != 0 {
					goto doublebreak
				} else {
					goto singlebreak
				}

			case *tracedump.TraceDetails:
				detail_msg, _ := msg.(*tracedump.TraceDetails)
				fmt.Printf("Last thread %d last position %d more_this_thread %d ",
					detail_msg.ThreadID, detail_msg.Position,
					detail_msg.MoreThisThread)
				fmt.Printf("more threads %d more this thread %d done %d\n",
					detail_msg.MoreThreads, detail_msg.MoreThisThread,
					detail_msg.Done)
				fmt.Printf("%s\n", detail_msg.TraceData)
				break
			}
		}
	singlebreak:
		stream.Close()
		need_close = false
	}

doublebreak:
	if need_close {
		stream.Close()
	}
}

func route_add_del_test(nroutes int, is_add bool) {
	var err error

	// Connect to VPP
	conn, err := govpp.Connect("/run/vpp/api.sock")

	if err != nil {
		fmt.Printf("Connect: %s\n", err.Error())
		return
	}

	defer conn.Disconnect()

	// Open channel
	ch, _ := conn.NewAPIChannel()
	defer ch.Close()

	rad := &ip.IPRouteAddDel2{IsAdd: true}
	rad_reply := &ip.IPRouteAddDel2Reply{}
	rad.Route.NPaths = 1
	rad.IsAdd = is_add

	path := fib_types.FibPath{
		Type:  fib_types.FIB_API_PATH_TYPE_DROP,
		Proto: fib_types.FIB_API_PATH_NH_PROTO_IP4,
	}
	rad.Route.Paths = make([]fib_types.FibPath, 1)
	rad.Route.Paths[0] = path

	var a, b, c, d, base int
	a = 1
	b = 2
	c = 3
	d = 4

	base = 0x01020304

	for i := 0; i < nroutes; i++ {
		a = ((base + i) & 0xFF000000) >> 24
		b = ((base + i) & 0x00FF0000) >> 16
		c = ((base + i) & 0x0000FF00) >> 8
		d = ((base + i) & 0x000000FF) >> 0

		s := fmt.Sprintf("%d.%d.%d.%d/32", a, b, c, d)

		prefix, err := ip_types.ParsePrefix(s)
		if err != nil {
			panic("prefix parse error")
			return
		}
		rad.Route.Prefix = prefix

		err = ch.SendRequest(rad).ReceiveReply(rad_reply)
		if err != nil {
			fmt.Printf("Add route reply %s\n", err.Error())
		}
	}
}

func async_route_add_del_test(nroutes int, is_add bool) {
	// Connect to VPP
	conn, err := govpp.Connect("/run/vpp/api.sock")

	if err != nil {
		fmt.Printf("Connect: %s\n", err.Error())
		return
	}
	defer conn.Disconnect()

	// Initialize the constant portion of the
	// route add-del message
	rad := &ip.IPRouteAddDel2{Reply: false}
	rad.Route.NPaths = 1
	rad.IsAdd = is_add

	path := fib_types.FibPath{
		Type:  fib_types.FIB_API_PATH_TYPE_DROP,
		Proto: fib_types.FIB_API_PATH_NH_PROTO_IP4,
	}
	rad.Route.Paths = make([]fib_types.FibPath, 1)
	rad.Route.Paths[0] = path

	ctx := context.Background()
	stream, err := conn.NewStream(ctx)
	if err != nil {
		panic(err)
	}

	defer stream.Close()

	// aka 1.2.3.4
	base := 0x01020304
	for i := 0; i < nroutes; i++ {
		a := ((base + i) & 0xFF000000) >> 24
		b := ((base + i) & 0x00FF0000) >> 16
		c := ((base + i) & 0x0000FF00) >> 8
		d := ((base + i) & 0x000000FF) >> 0

		rad.Route.Prefix = ip_types.Prefix{
			Len: 32,
			Address: ip_types.Address{
				Af: ip_types.ADDRESS_IP4,
				Un: ip_types.AddressUnion{
					XXX_UnionData: [16]byte{byte(a), byte(b),
						byte(c), byte(d)},
				},
			},
		}
		// Unless this is the last route, we don't want a reply
		rad.Reply = false
		if i == nroutes-1 {
			rad.Reply = true
		}

		// Send the message
		err = stream.SendMsg(rad)
		if err != nil {
			fmt.Printf("SendMsg reply %s\n", err.Error())
			break
		}

		// Time to go look for a reply?
		if rad.Reply == true {
			msg, err := stream.RecvMsg()
			if err != nil {
				fmt.Printf("RecvMsg failed: %s\n", err.Error())
				break
			}
			rad_reply, _ := msg.(*ip.IPRouteAddDel2Reply)
			if rad_reply.Retval != 0 {
				fmt.Printf("Error return %d:\n", rad_reply.Retval)
				break
			}
		}
	}
}

func route_test(nroutes int, async bool) {
	fmt.Printf("Add %d routes...\n", nroutes)
	start := time.Now()

	if async {
		async_route_add_del_test(nroutes, true)
	} else {
		route_add_del_test(nroutes, true)
	}

	end := time.Now()
	delta := end.Sub(start)
	delta_sec := float64(delta) * 1e-9
	fmt.Printf("Done in %.6fs, %.2f routes/sec\n", delta_sec,
		float64(nroutes)/delta_sec)

	fmt.Printf("Delete %d routes...\n", nroutes)
	start = time.Now()

	if async {
		async_route_add_del_test(nroutes, false)
	} else {
		route_add_del_test(nroutes, false)
	}
	end = time.Now()
	delta = end.Sub(start)
	delta_sec = float64(delta) * 1e-9
	fmt.Printf("Done in %.6fs, %.2f routes/sec\n", float64(delta)*1e-9,
		float64(nroutes)/delta_sec)
}

func async_route_add_file_test(data []byte, is_add bool) (nroutes int) {
	// Connect to VPP
	conn, err := govpp.Connect("/run/vpp/api.sock")

	if err != nil {
		fmt.Printf("Connect: %s\n", err.Error())
		return
	}
	defer conn.Disconnect()

	// Initialize the constant portion of the
	// route add-del message
	rad := &ip.IPRouteAddDel2{IsAdd: true}
	rad.Route.NPaths = 1
	rad.IsAdd = is_add

	path := fib_types.FibPath{
		Type:  fib_types.FIB_API_PATH_TYPE_DROP,
		Proto: fib_types.FIB_API_PATH_NH_PROTO_IP4,
	}
	rad.Route.Paths = make([]fib_types.FibPath, 1)
	rad.Route.Paths[0] = path

	ctx := context.Background()
	stream, err := conn.NewStream(ctx)
	if err != nil {
		panic(err)
	}

	defer stream.Close()
	cp := 0

	for nroutes = 0; cp < len(data); nroutes++ {
		digit := 0
		for ; data[cp] != '.'; cp++ {
			digit = 10*digit + int(data[cp]) - '0'
		}
		a := digit
		cp++

		digit = 0
		for ; data[cp] != '.'; cp++ {
			digit = 10*digit + int(data[cp]) - '0'
		}
		b := digit
		cp++

		digit = 0
		for ; data[cp] != '.'; cp++ {
			digit = 10*digit + int(data[cp]) - '0'
		}
		c := digit
		cp++

		digit = 0
		for ; data[cp] != '/'; cp++ {
			digit = 10*digit + int(data[cp]) - '0'
		}
		d := digit
		cp++

		digit = 0
		for ; data[cp] != '\n'; cp++ {
			digit = 10*digit + int(data[cp]) - '0'
		}
		prefixlen := digit
		cp++

		rad.Route.Prefix = ip_types.Prefix{
			Len: uint8(prefixlen),
			Address: ip_types.Address{
				Af: ip_types.ADDRESS_IP4,
				Un: ip_types.AddressUnion{
					XXX_UnionData: [16]byte{byte(a), byte(b),
						byte(c), byte(d)},
				},
			},
		}
		// Unless this is the last route, we don't want a reply
		rad.Reply = false
		if cp >= len(data) {
			rad.Reply = true
		}

		// Send the message
		err = stream.SendMsg(rad)
		if err != nil {
			fmt.Printf("SendMsg reply %s\n", err.Error())
			break
		}

		// Time to go look for a reply?
		if rad.Reply == true {
			msg, err := stream.RecvMsg()
			if err != nil {
				fmt.Printf("RecvMsg failed: %s\n", err.Error())
				break
			}
			rad_reply, _ := msg.(*ip.IPRouteAddDel2Reply)
			if rad_reply.Retval != 0 {
				fmt.Printf("Error return %d:\n", rad_reply.Retval)
				break
			}
		}
	}
	return
}

func route_file_test(data []byte) {
	fmt.Printf("Add routes from file...\n")
	start := time.Now()

	nroutes := async_route_add_file_test(data, true)

	end := time.Now()
	delta := end.Sub(start)
	delta_sec := float64(delta) * 1e-9
	fmt.Printf("Done in %.6fs, %d routes, %.2f routes/sec\n", delta_sec,
		nroutes, float64(nroutes)/delta_sec)

	fmt.Printf("Delete %d routes...\n", nroutes)
	start = time.Now()

	_ = async_route_add_file_test(data, false)

	end = time.Now()
	delta = end.Sub(start)
	delta_sec = float64(delta) * 1e-9
	fmt.Printf("Done in %.6fs, %.2f routes/sec\n", float64(delta)*1e-9,
		float64(nroutes)/delta_sec)
}

func main() {
	argv := os.Args

	if len(argv) < 2 {
		goto usage
	}

	if strings.Compare(argv[1], "tracedump") == 0 {
		tracedump_test()
		return
	}
	if strings.Compare(argv[1], "route") == 0 {
		nroutes, err := strconv.Atoi(argv[2])
		if err != nil {
			panic("number of routes missing, or didn't parse")
		}
		route_test(nroutes, false)
		return
	}
	if strings.Compare(argv[1], "async-route") == 0 {
		nroutes, err := strconv.Atoi(argv[2])
		if err != nil {
			panic("number of routes missing, or didn't parse")
		}
		route_test(nroutes, true)
		return
	}

	if strings.Compare(argv[1], "file") == 0 {
		data, err := ioutil.ReadFile(argv[2])
		if err != nil {
			panic("Couldn't open input file")
		}
		route_file_test(data)
		return
	}

usage:
	fmt.Printf("Usage: %s tracedump | route NNN\n", argv[0])
}

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	vppIfStatsVersion		= "2.0.4"

	defaultPort             = 7670
	vppConnectionRetryDelay = 10
	vppConnectionRetryLimit = 60
)

type vppRestConnector struct {
	*VppConnector

	// Mutex to prevent concurrent data modification
	mutex sync.Mutex
}

var vppConn *vppRestConnector

func getInterfacesAndStats(w http.ResponseWriter) {
	vppConn.mutex.Lock()
	defer vppConn.mutex.Unlock()
	Logger.Debugf("Fetching interfaces")
	if err := vppConn.GetInterfaces(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	Logger.Debugf("Fetched interfaces")
	Logger.Debugf("Fetching stats")
	if err := vppConn.GetStatsForAllInterfaces(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	Logger.Debugf("Fetched stats")
}

func recoverFromFatalError(w http.ResponseWriter) {
	if r := recover(); r != nil {
		Logger.Warnf("Recover return data: %v", r)
		http.Error(w, fmt.Sprintf("%v", r), http.StatusInternalServerError)
	}
}

func scrapeHandler(w http.ResponseWriter, r *http.Request) {
	Logger.Debugf("Processing request from %v to %v", r.URL, r.Host)
	defer recoverFromFatalError(w)
	getInterfacesAndStats(w)

	jsonString, err := vppConn.DumpToJson()
	if err != nil {
		Logger.Debug("Failed to dump data to json")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonString)
	Logger.Debug("Writing response")
	if err != nil {
		Logger.Debugf("Error while writing response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	Logger.Debugf("%v %v --- %v %v\n", r.Method, r.URL, http.StatusOK, http.StatusText(http.StatusOK))
}

func main() {
	versionPtr := flag.Bool("v", false, "Prints vppifstats version")
	portPtr := flag.Int("port", defaultPort, "Port to listen on")
	apiSocketPathPtr := flag.String("api_socket_path", DefaultAPISocketPath, "Path to VPP API socket")
	statsSocketPathPtr := flag.String("stats_socket_path", DefaultStatsSocketPath, "Path to VPP stats socket")
	noConnRetryLimitPtr := flag.Bool("no_retry_limit", false, "If specified, will try to connect to VPP indefinitely")
	logLevelPtr := flag.String("log_level", "INFO", "Log level: (DEBUG, INFO, WARN or ERROR)")
	shmPrefixPtr := flag.String("shm_prefix", DefaultShmPrefix, "Shared memory prefix (advanced)")
	flag.Parse()

	if *versionPtr == true {
		fmt.Println(vppIfStatsVersion)
		os.Exit(0)
	}

	Logger.SetLevelFromString(*logLevelPtr)

	vppConn = &vppRestConnector{
		VppConnector: NewVppConnector(*apiSocketPathPtr, *statsSocketPathPtr, *shmPrefixPtr),
	}
	defer vppConn.Disconnect()

	retries := 0
	for {
		if err := vppConn.Connect(); err != nil {
			if *noConnRetryLimitPtr == false && retries >= vppConnectionRetryLimit {
				Logger.Crit(err)
			}
			retries++
			Logger.Infof("Connection to VPP failed. Retry #%v", retries)
			time.Sleep(vppConnectionRetryDelay * time.Second)
		} else {
			break
		}
	}

	if err := vppConn.GetVppVersion(); err != nil {
		Logger.Error(err)
		time.Sleep(vppConnectionRetryDelay)
		err = vppConn.GetVppVersion()
		if err != nil {
			Logger.Crit(err)
		}
	}

	http.HandleFunc("/", scrapeHandler)

	address := fmt.Sprintf("localhost:%v", *portPtr)
	Logger.Infof("Listening on %v\n", address)
	Logger.Crit(http.ListenAndServe(address, nil))
}

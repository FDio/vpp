package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"
)

func bytesToString(b []byte) string {
	return string(bytes.Split(b, []byte{0})[0])
}

func parseMacAddress(l2Address []byte, l2AddressLength uint32) string {
	var mac string
	for i := uint32(0); i < l2AddressLength; i++ {
		mac += fmt.Sprintf("%02x", l2Address[i])
		if i < l2AddressLength-1 {
			mac += ":"
		}
	}
	return mac
}

type logLevel uint8

const (
	NOTSET logLevel = iota
	DEBUG
	INFO
	WARNING
	ERROR
	CRITICAL
)

type logger struct {
	level logLevel
}

func (l *logger) SetLevel(level logLevel) {
	l.level = level
}

func (l *logger) SetLevelFromString(level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		l.SetLevel(DEBUG)
	case "INFO":
		l.SetLevel(INFO)
	case "WARN":
	case "WARNING":
		l.SetLevel(WARNING)
	case "ERROR":
		l.SetLevel(ERROR)
	case "CRITICAL":
		l.SetLevel(CRITICAL)
	default:
		l.SetLevel(NOTSET)
	}
}

func (l *logger) log(level logLevel, prefix string, message string, args ...interface{}) {
	if level >= l.level {
		var msg string
		if message != "" {
			msg = fmt.Sprintf(message, args...)
		} else {
			msg = fmt.Sprintln(args...)
		}

		ts := time.Now().Format("2006-01-02T15:04:05.999Z")
		fmt.Printf("%v|%v|%v\n", ts, prefix, msg)
	}
}

func (l *logger) Debugf(message string, args ...interface{}) {
	l.log(DEBUG, "DEBUG", message, args...)
}

func (l *logger) Debug(args ...interface{}) {
	l.log(DEBUG, "DEBUG", "%v", args...)
}

func (l *logger) Infof(message string, args ...interface{}) {
	l.log(INFO, "INFO", message, args...)
}

func (l *logger) Info(args ...interface{}) {
	l.log(INFO, "INFO", "%v", args...)
}

func (l *logger) Warnf(message string, args ...interface{}) {
	l.log(WARNING, "WARNING", message, args...)
}

func (l *logger) Warn(args ...interface{}) {
	l.log(WARNING, "WARNING", "%v", args...)
}

func (l *logger) Errorf(message string, args ...interface{}) {
	l.log(ERROR, "ERROR", message, args...)
}

func (l *logger) Error(args ...interface{}) {
	l.log(ERROR, "ERROR", "%v", args...)
}

func (l *logger) Critf(message string, args ...interface{}) {
	l.log(CRITICAL, "CRITICAL", message, args...)
	os.Exit(1)
}

func (l *logger) Crit(args ...interface{}) {
	l.log(CRITICAL, "CRITICAL", "%v", args...)
	os.Exit(1)
}

var Logger = logger{level: INFO}

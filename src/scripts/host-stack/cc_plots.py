#!/usr/bin/env python3

import argparse
import re
import sys

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


class Point():
    "CC event"
    def __init__(self, x, y):
        self.x = x
        self.y = y

def listx(points):
  return list(map(lambda pt: pt.x, points))

def listy(points):
  return list(map(lambda pt: pt.y, points))

def plot_data(d):

  plt.figure(1)

  cwndx = listx(d["cwnd"])
  cwndy = listy(d["cwnd"])
  congx = listx(d["congestion"])
  congy = listy(d["congestion"])
  rcvrdx = listx(d["recovered"])
  rcvrdy = listy(d["recovered"])
  rxttx = listx(d["rxtTimeout"])
  rxtty = listy(d["rxtTimeout"])

  # cwnd/ssthresh/cc events
  plt.subplot(311)
  plt.title("cwnd/ssthresh")
  pcwnd = plt.plot(cwndx, cwndy, 'r')
  psst = plt.plot(cwndx, d["ssthresh"], 'y-')
  pcong = plt.plot(congx, congy,'yo')
  precov = plt.plot(rcvrdx, rcvrdy,'co')
  prxtt = plt.plot(rxttx, rxtty,'mo')

  marker1 = Line2D(range(1), range(1), color="r")
  marker2 = Line2D(range(1), range(1), color="y")
  marker3 = Line2D(range(1), range(1), color="w", marker="o", markerfacecolor="y")
  marker4 = Line2D(range(1), range(1), color="w", marker="o", markerfacecolor="c")
  marker5 = Line2D(range(1), range(1), color="w", marker="o", markerfacecolor="m")
  plt.legend((marker1, marker2, marker3, marker4, marker5),
             ('cwnd', 'ssthresh', 'congestion', 'recovered', 'rxt-timeout'),
             loc=4)
  axes = plt.gca()
  axes.set_ylim([-20e4, max(cwndy) + 20e4])

  # snd variables
  plt.subplot(312)
  plt.title("cc variables")
  plt.plot(cwndx, d["space"], 'g-', markersize=1)
  plt.plot(cwndx, d["flight"], 'b-', markersize=1)
  plt.plot(cwndx, d["sacked"], 'm:', markersize=1)
  plt.plot(cwndx, d["lost"], 'y:', markersize=1)
  plt.plot(cwndx, d["cc-space"], 'k:', markersize=1)
  plt.plot(cwndx, cwndy, 'ro', markersize=2)

  plt.plot(congx, congy, 'y^', markersize=10, markerfacecolor="y")
  plt.plot(rcvrdx, rcvrdy, 'c^', markersize=10, markerfacecolor="c")
  plt.plot(rxttx, rxtty, 'm^', markersize=10, markerfacecolor="m")

  #plt.plot(cwndx, d["snd_wnd"], 'ko', markersize=1)
  plt.legend(("snd-space", "flight", "sacked", "lost", "cc-space", "cwnd",
              "congestion", "recovered", "rxt-timeout"),
             loc=1)

  # rto/srrt/rttvar
  plt.subplot(313)
  plt.title("rtt")
  plt.plot(cwndx, d["srtt"], 'g-')
  plt.plot(cwndx, [x/1000 for x in d["mrtt-us"]], 'r-')
  plt.plot(cwndx, d["rttvar"], 'b-')
  plt.legend(["srtt", "mrtt-us", "rttvar"])
  axes = plt.gca()
  #plt.plot(cwndx, rto, 'r-')
  #axes.set_ylim([0, int(max(rto[2:len(rto)])) + 50])

  # show
  plt.show()

def find_pattern(file_path,session_idx):
    is_active_open = 1
    listener_pattern = "l\[\d\]"
    if (is_active_open):
      initial_pattern = "\[\d\](\.\d+:\d+\->\.\d+:\d+)\s+open:\s"
    else:
      initial_pattern = "\[\d\](\.\d+:\d+\->\.\d+:\d+)\s"
    idx = 0
    f = open(file_path, 'r')
    for line in f:
      # skip listener lines (server)
      if (re.search(listener_pattern, line) != None):
        continue
      match = re.search(initial_pattern, line)
      if (match == None):
        continue
      if (idx < session_idx):
        idx += 1
        continue
      filter_pattern = str(match.group(1)) + "\s+(.+)"
      print ("pattern is %s" % filter_pattern)
      f.close()
      return filter_pattern
    raise Exception ("Could not find initial pattern")

def compute_time(min, sec, msec):
  return int(min)*60 + int(sec) + int(msec)/1000.0

def run(file_path, session_idx):
    filter_sessions = 1
    filter_pattern = ""

    patterns = {
      "time"      : "^\d+:(\d+):(\d+):(\d+):\d+",
      "listener"  : "l\[\d\]",
      "cc"        : "cwnd (\d+) flight (\d+) space (\d+) ssthresh (\d+) snd_wnd (\d+)",
      "cc-snd"    : "cc_space (\d+) sacked (\d+) lost (\d+)",
      "rtt"       : "rto (\d+) srtt (\d+) mrtt-us (\d+) rttvar (\d+)",
      "rxtt"      : "rxt-timeout",
      "congestion": "congestion",
      "recovered" : "recovered",
    }
    d = {
      "cwnd"        : [],
      "space"       : [],
      "flight"      : [],
      "ssthresh"    : [],
      "snd_wnd"     : [],
      "cc-space"    : [],
      "lost"        : [],
      "sacked"      : [],
      "rto"         : [],
      "srtt"        : [],
      "mrtt-us"     : [],
      "rttvar"      : [],
      "rxtTimeout"  : [],
      "congestion"  : [],
      "recovered"   : [],
    }

    if (filter_sessions):
        filter_pattern = find_pattern(file_path, session_idx)
    f = open(file_path, 'r')

    stats_index = 0
    start_time = 0

    for line in f:
        # skip listener lines (server)
        if (re.search(patterns["listener"], line) != None):
            continue
        # filter sessions
        if (filter_sessions):
            match = re.search(filter_pattern, line)
            if (match == None):
                continue

        original_line = line
        line = match.group(1)
        match = re.search (patterns["time"], original_line)
        if (match == None):
          print "something went wrong! no time!"
          continue
        time = compute_time (match.group(1), match.group(2), match.group(3))
        if (start_time == 0):
          start_time = time

        time = time - start_time
        match = re.search(patterns["cc"], line)
        if (match != None):
          d["cwnd"].append(Point(time, int(match.group(1))))
          d["flight"].append(int(match.group(2)))
          d["space"].append(int(match.group(3)))
          d["ssthresh"].append(int(match.group(4)))
          d["snd_wnd"].append(int(match.group(5)))
          stats_index += 1
          continue
        match = re.search(patterns["cc-snd"], line)
        if (match != None):
          d["cc-space"].append(int(match.group(1)))
          d["sacked"].append(int(match.group(2)))
          d["lost"].append(int(match.group(3)))
        match = re.search(patterns["rtt"], line)
        if (match != None):
           d["rto"].append(int(match.group(1)))
           d["srtt"].append(int(match.group(2)))
           d["mrtt-us"].append(int(match.group(3)))
           d["rttvar"].append(int(match.group(4)))
        if (stats_index == 0):
           continue
        match = re.search(patterns["rxtt"], line)
        if (match != None):
          d["rxtTimeout"].append(Point(time, d["cwnd"][stats_index - 1].y + 1e4))
          continue
        match = re.search(patterns["congestion"], line)
        if (match != None):
          d["congestion"].append(Point(time, d["cwnd"][stats_index - 1].y - 1e4))
          continue
        match = re.search(patterns["recovered"], line)
        if (match != None):
          d["recovered"].append(Point(time, d["cwnd"][stats_index - 1].y))
          continue

    plot_data(d)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot tcp cc logs")
    parser.add_argument('-f', action='store', dest='file', required=True,
                        help="elog file in txt format")
    parser.add_argument('-s', action='store', dest='session_index', default=0,
                        help="session index for which to plot cc logs" )
    results = parser.parse_args()
    run(results.file, int(results.session_index))

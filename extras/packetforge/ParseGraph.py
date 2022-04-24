# Copyright (c) 2022 Intel and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ProtocolHeader import *
from ForgeResult import *
from Node import *
from Edge import *
import os


class ParseGraph:
    def __init__(self):
        self.nodeDict = {}
        self.edgeDict = {}

    def Create(folder):
        try:
            pg = ParseGraph()
            if not os.path.exists(folder):
                print("folder not exisit")
                return None

            if os.path.exists(folder + "/nodes"):
                pg.LoadNodesFromDirectory(folder + "/nodes")
            if os.path.exists(folder + "/edges"):
                pg.LoadEdgesFromDirectory(folder + "/edges")
        except:
            print("Failed to create Parse Graph")
            return None
        else:
            return pg

    def Nodes(self):
        nodes = []
        nodes.extend(self.nodeDict.values)
        return nodes

    def Edges(self):
        edges = []
        edges.extend(self.edgeDict.values)
        return edges

    def LoadNodesFromDirectory(self, folder):
        for root, dirs, files in os.walk(folder):
            for f in files:
                self.LoadNodeFromFile(os.path.join(root, f))

    def LoadEdgesFromDirectory(self, folder):
        for root, dirs, files in os.walk(folder):
            for f in files:
                self.LoadEdgeFromFile(os.path.join(root, f))

    def LoadNodeFromFile(self, file):
        try:
            node = Node.Create(file)

            if node == None:
                print("No node created")
                return None

            self.AddNode(node)
        except:
            print("Failed to create node from " + file)

    def LoadEdgeFromFile(self, file):
        try:
            edges = Edge.Create(file)

            if edges == None:
                print("No edge created")
                return None

            for edge in edges:
                self.AddEdge(edge)
        except:
            print("Failed to create edge from " + file)

    def createProtocolHeader(self, name):
        if name in self.nodeDict:
            return ProtocolHeader(self.nodeDict[name])
        return None

    def GetNode(self, name):
        if self.nodeDict.has_key(name):
            return self.nodeDict[name]
        return None

    def GetEdge(self, start, end):
        key = start + "-" + end
        if key in self.edgeDict:
            return self.edgeDict[key]
        return None

    def AddNode(self, node):
        if node.Name in self.nodeDict:
            print("Warning: node {0} already exist", node.Name)

        self.nodeDict[node.Name] = node

    def AddEdge(self, edge):
        key = edge.Start + "-" + edge.End
        if key in self.edgeDict:
            print("Warning: edge {0} already exist", key)
        self.edgeDict[key] = edge

    def Forge(self, path):
        headerList = []

        # set field value/mask
        for headerConfig in path.stack:
            header = self.createProtocolHeader(headerConfig.Header)

            if header == None:
                return None

            for hcf in headerConfig.fields:
                attr = False
                if not header.SetField(hcf.Name, hcf.Value):
                    if not header.SetAttribute(hcf.Name, hcf.Value):
                        print("failed to set value of " + hcf.Name)
                        return None
                    else:
                        attr = True

                if not attr and not header.SetMask(hcf.Name, hcf.Mask):
                    print("failed to set mask of " + hcf.Name)
                    return None

            header.Adjust()

            headerList.append(header)

        # apply edge actions and length autoincrease
        for i in range(1, len(headerList)):
            start = headerList[i - 1]
            end = headerList[i]

            edge = self.GetEdge(start.Name(), end.Name())

            if edge == None:
                print("no edge exist for {0}, {1}", start.Name, end.Name)
                return None

            edge.Apply(start, end)

            increase = end.GetSize()
            for j in range(i):
                headerList[j].AppendAuto(increase)

        # resolve buffer
        pktLen = 0
        for header in headerList:
            header.Resolve()
            pktLen += len(header.Buffer)

        # join buffer
        pktbuf = []
        mskbuf = []

        offset = 0
        for header in headerList:
            pktbuf.extend(header.Buffer)
            mskbuf.extend(header.Mask)

            offset += len(header.Buffer)

        result = ForgeResult(headerList, pktbuf, mskbuf)

        return result

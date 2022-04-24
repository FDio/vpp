from EdgeAction import *
import json

class Edge:

    def __init__(self):
        self.JSON = None
        self.Start = None
        self.End = None
        self.actionList = []

    def Create(jsonfile):
        f = open(jsonfile, 'r', encoding='utf-8')
        token = json.load(f)

        if (token == None):
            return None

        if (token["type"] != "edge"):
            return None

        edgeList = []

        startNodes = token["start"]
        endNodes = token["end"]

        if (startNodes == None or endNodes == None):
            return None

        startTokens = startNodes.split(',')
        endTokens = endNodes.split(',')

        for start in startTokens:
            for end in endTokens:

                edge = Edge()

                edge.Start = start
                edge.End = end

                if ("actions" in token):
                    for at in token["actions"]:
                        action = EdgeAction.Create(at)
                        if (not action):
                            return None

                        edge.actionList.append(action)

                edge.JSON = jsonfile
                edgeList.append(edge)

        return edgeList

    def Apply(self, first, second):
        exp = []

        for i in range(len(self.actionList)):
            act = self.actionList[i]

            if (act.FromStartObject == True):
                exp.append(first.GetValue(act.FromExpression))
            elif (act.FromStartObject == False):
                exp.append(second.GetValue(act.FromExpression))
            else:
                exp.append(act.FromExpression)

        for i in range(len(exp)):
            act = self.actionList[i]

            if (act.ToStartObject):
                first.SetFieldAuto(act.ToExpression, exp[i])
            else:
                second.SetFieldAuto(act.ToExpression, exp[i])

    def Actions(self):
        return self.actionList

    def Name(self):
        return self.Start + '_' + self.End

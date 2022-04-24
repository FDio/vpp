from PathNode import *

class Path:

    def __init__(self):
        self.stack = []

    def Create(token):
        try:
            path = Path()
            ss = token["stack"]

            if (ss == None):
                return None

            for hct in ss:
                path.stack.append(PathNode.Create(hct))

            return path
        except:
            print("Failed to create Path from jsonfile")
            return None

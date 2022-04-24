from PathNodeField import *

class PathNode:

    def __init__(self):
        self.Header = None
        self.fields = []

    def Create(token):
        if (token == None):
            return None

        config = PathNode()

        if ("header" in token):
            config.Header = token["header"]
            if (config.Header == None):
                return None

        if ("fields" in token):
            fts = token["fields"]
            if (fts != None):
                for ft in fts:
                    config.fields.append(PathNodeField.Create(ft))

        return config

class EdgeAction:

    def __init__(self):
        self.ToStartObject = None
        self.ToExpression = None
        self.FromStartObject = None
        self.FromExpression = None

    def Create(token):
        if (token == None):
            return None

        dststr = token["dst"]
        srcstr = token["src"]

        if (srcstr == None or dststr == None):
            return None

        action = EdgeAction()

        dststr = dststr.strip()
        srcstr = srcstr.strip()


        if (dststr.startswith("start.")):
            action.ToStartObject = True
            action.ToExpression = dststr[6:]
        elif (dststr.startswith("end.")):
            action.ToStartObject = False
            action.ToExpression = dststr[4:]
        else:
            return None

        if (srcstr.startswith("start.")):
            action.FromStartObject = True
            action.FromExpression = srcstr[6:]
        elif (srcstr.startswith("end.")):
            action.FromStartObject = False
            action.FromExpression = srcstr[4:]
        else:
            action.FromExpression = srcstr

        return action

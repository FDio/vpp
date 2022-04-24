class PathNodeField:

    def __init__(self):
        self.Name = None
        self.Value = None
        self.Mask = None

    def Create(token):
        if (token == None):
            return None

        field = PathNodeField()

        if ('name' in token):
            field.Name = token["name"]
        if ('value' in token):
            field.Value = token["value"]
        if ('mask' in token):
            field.Mask = token["mask"]

        if (field.Name == None):
            return None

        return field

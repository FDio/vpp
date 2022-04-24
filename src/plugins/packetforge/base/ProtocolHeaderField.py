import ExpressionConverter

class ProtocolHeaderField:

    def __init__(self, Size, Value, Mask, Field):
        self.Size = Size
        self.Value = Value
        self.Mask = Mask
        self.Field = Field

    def UpdateValue(self, expression, auto):
        if (self.Field.IsReadonly and not auto):
            return False

        if (expression != None):
            ret, _ = ExpressionConverter.Verify(self.Field.Format, expression)
            if (not ret):
                return False

        self.Value = expression
        return True

    def UpdateMask(self, expression):
        if (expression != None):
            ret, _ = ExpressionConverter.Verify(self.Field.Format, expression)
            if (not ret):
                return False

        self.Mask = expression
        return True

    def UpdateSize(self):
        if (self.Size):
            return
        self.Size = self.Field.Size

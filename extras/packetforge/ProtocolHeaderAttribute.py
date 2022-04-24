import ExpressionConverter


class ProtocolHeaderAttribute:
    def __init__(self, Size, Value, Attribute):
        self.Size = Size
        self.Value = Value
        self.Attribute = Attribute

    def UpdateValue(self, expression):
        ret, expression = ExpressionConverter.Verify(self.Attribute.Format, expression)
        if not ret:
            return False

        self.Value = expression
        return True

import ExpressionConverter


class ForgeResult:
    def __init__(self, Header, PacketBuffer, MaskBuffer):
        self.Headers = Header
        self.PacketBuffer = PacketBuffer
        self.MaskBuffer = MaskBuffer

    def ToJSON(self):
        result = {}
        result["Length"] = str(len(self.PacketBuffer))
        result["Packet"] = ExpressionConverter.ByteArrayToString(self.PacketBuffer)
        result["Mask"] = ExpressionConverter.ByteArrayToString(self.MaskBuffer)
        result["Protocol Stack"] = []

        for header in self.Headers:
            head_info = {}
            head_info["name"] = header.Name()
            head_info["Fields"] = []
            for field in header.fields:
                if field.Size == 0:
                    continue
                field_info = {}
                field_info["name"] = field.Field.Name
                field_info["size"] = str(field.Size)
                field_info["value"] = field.Value
                field_info["mask"] = field.Mask
                head_info["Fields"].append(field_info)
            result["Protocol Stack"].append(head_info)

        return result

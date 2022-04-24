from NodeField import *
from NodeAttribute import *
import json


class Node:
    def __init__(self):
        self.fields = []
        self.attributes = []
        self.attrsDict = {}
        self.fieldDict = {}

    def Create(jsonfile):
        f = open(jsonfile, "r", encoding="utf-8")
        token = json.load(f)

        if token == None:
            return None

        if token["type"] != "node":
            return None

        node = Node()

        name = token["name"]
        if name == None:
            return None

        node.Name = name

        if token["layout"] == None:
            return None

        for ft in token["layout"]:
            field = NodeField.Create(ft)
            if field == None:
                return None
            node.fields.append(field)
            if not field.IsReserved:
                node.fieldDict[field.Name] = field

        if "attributes" in token and token["attributes"] != None:
            for ft in token["attributes"]:
                attr = NodeAttribute.Create(ft)
                node.attrsDict[attr.Name] = attr
                node.attributes.append(attr)

        node.JSON = jsonfile
        return node

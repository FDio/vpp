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

import cgi, pyparsing as pp

# Some useful primitives
ident = pp.Word(pp.alphas + "_", pp.alphas + pp.nums + "_")
intNum = pp.Word(pp.nums)
hexNum = pp.Literal("0x") + pp.Word(pp.hexnums)
octalNum = pp.Literal("0") + pp.Word("01234567")
integer = (hexNum | octalNum | intNum) + \
    pp.Optional(pp.Literal("ULL") | pp.Literal("LL") | pp.Literal("L"))
floatNum = pp.Regex(r'\d+(\.\d*)?([eE]\d+)?') + pp.Optional(pp.Literal("f"))
char = pp.Literal("'") + pp.Word(pp.printables, exact=1) + pp.Literal("'")
arrayIndex = integer | ident

lbracket = pp.Literal("(").suppress()
rbracket = pp.Literal(")").suppress()
lbrace = pp.Literal("{").suppress()
rbrace = pp.Literal("}").suppress()
comma = pp.Literal(",").suppress()
equals = pp.Literal("=").suppress()
dot = pp.Literal(".").suppress()
semicolon = pp.Literal(";").suppress()

# initializer := { [member = ] (variable | expression | { initializer } ) }
typeName = ident
varName = ident
typeSpec = pp.Optional("unsigned") + \
           pp.oneOf("int long short float double char u8 i8 void") + \
           pp.Optional(pp.Word("*"), default="")
typeCast = pp.Combine( "(" + ( typeSpec | typeName ) + ")" ).suppress()

string = pp.Combine(pp.OneOrMore(pp.QuotedString(quoteChar='"',
    escChar='\\', multiline=True)), adjacent=False)
literal = pp.Optional(typeCast) + (integer | floatNum | char | string)
var = pp.Combine(pp.Optional(typeCast) + varName +
    pp.Optional("[" + arrayIndex + "]"))

# This could be more complete, but suffices for our uses
expr = (literal | var)

"""Parse and render a block of text into a Python dictionary."""
class Parser(object):
    """Compiled PyParsing BNF"""
    _parser = None

    def __init__(self):
        super(Parser, self).__init__()
        self._parser = self.BNF()

    def BNF(self):
        raise NotImplementedError

    def item(self, item):
        raise NotImplementedError

    def parse(self, input):
        item = self._parser.parseString(input).asList()
        return self.item(item)


"""Parser for function-like macros - without the closing semi-colon."""
class ParserFunctionMacro(Parser):
    def BNF(self):
        # VLIB_CONFIG_FUNCTION (unix_config, "unix")
        macroName = ident
        params = pp.Group(pp.ZeroOrMore(expr + comma) + expr)
        macroParams = lbracket + params + rbracket

        return macroName + macroParams

    def item(self, item):
        r = {
            "macro": item[0],
            "name": item[1][1],
            "function": item[1][0],
        }

        return r


"""Parser for function-like macros with a closing semi-colon."""
class ParseFunctionMacroStmt(ParserFunctionMacro):
    def BNF(self):
        # VLIB_CONFIG_FUNCTION (unix_config, "unix");
        function_macro = super(ParseFunctionMacroStmt, self).BNF()
        mi = function_macro + semicolon
        mi.ignore(pp.cppStyleComment)

        return mi


"""
Parser for our struct initializers which are composed from a
function-like macro, equals sign, and then a normal C struct initalizer
block.
"""
class MacroInitializer(ParserFunctionMacro):
    def BNF(self):
        # VLIB_CLI_COMMAND (show_sr_tunnel_command, static) = {
        #    .path = "show sr tunnel",
        #    .short_help = "show sr tunnel [name <sr-tunnel-name>]",
        #    .function = show_sr_tunnel_fn,
        # };
        cs = pp.Forward()


        member = pp.Combine(dot + varName + pp.Optional("[" + arrayIndex + "]"),
            adjacent=False)
        value = (expr | cs)

        entry = pp.Group(pp.Optional(member + equals, default="") + value)
        entries = (pp.ZeroOrMore(entry + comma) + entry + pp.Optional(comma)) | \
                  (pp.ZeroOrMore(entry + comma))

        cs << (lbrace + entries + rbrace)

        macroName = ident
        params = pp.Group(pp.ZeroOrMore(expr + comma) + expr)
        macroParams = lbracket + params + rbracket

        function_macro = super(MacroInitializer, self).BNF()
        mi = function_macro + equals + pp.Group(cs) + semicolon
        mi.ignore(pp.cppStyleComment)

        return mi

    def item(self, item):
        r = {
            "macro": item[0],
            "name": item[1][0],
            "params": item[2],
            "value": {},
        }

        for param in item[2]:
            r["value"][param[0]] = cgi.escape(param[1])

        return r

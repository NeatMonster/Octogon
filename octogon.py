import argparse
import inspect
import json
import re
import string
import sys

from pycparser import c_parser, c_ast
cparser = c_parser.CParser()

REGISTER_SIZES = {
    "R": 32,
    "RR": 64,
    "C": 32,
    "CC": 64,
    "G": 32,
    "GG": 64,
    "S": 32,
    "SS": 64,
    "P": 8,
    "M": 32,
    "N": 32,
    "r": 32,
}

REGISTER_NAMES = {
    "R": ["R{}".format(i) for i in range(32)],
    "RR": ["R{}_{}".format(i + 1, i) if i % 2 == 0 else "_" for i in range(0, 32)],
    "C": ["C{}".format(i) for i in range(32)],
    "CC": ["C{}_{}".format(i + 1, i) if i % 2 == 0 else "_" for i in range(0, 32)],
    "G": ["G{}".format(i) for i in range(32)],
    "GG": ["G{}_{}".format(i + 1, i) if i % 2 == 0 else "_" for i in range(0, 32)],
    "S": ["S{}".format(i) for i in range(32)],
    "SS": ["S{}_{}".format(i + 1, i) if i % 2 == 0 else "_" for i in range(0, 32)],
    "P": ["P{}".format(i) for i in range(4)],
    "M": ["$(M{})".format(i) for i in range(2)],
    "r": ["R{}".format(i) for i in list(range(0, 8)) + list(range(16, 24))],
}

REGISTER_ALIASES = {
    "R": ["SP", "FP", "LR"],
    "RR": ["LR_FP"],
    "C": ["SA0", "LC0", "SA1", "LC1", "P3_0", "M0", "M1",
            "USR", "PC", "UGP", "GP", "CS0", "CS1",
            "UPCYCLELO", "UPCYCLEHI", "FRAMELIMIT", "FRAMEKEY",
            "PKTCOUNTLO", "PKTCOUNTHI", "UTIMERLO", "UTIMERHI"],
    "CC": ["UPCYCLE", "PKTCOUNT", "UTIMER"],
    "G": ["GISDBMBXIN", "GISDBMBXOUT", "GPCYCLELO", "GPCYCLEHI",
            "GPMUCNT0", "GPMUCNT1", "GPMUCNT2", "GPMUCNT3"],
    "S": ["SGP0", "SGP1", "STID", "ELR", "BADVA0", "BADVA1", "SSR",
            "CCR", "HTID", "BADVA", "IMASK", "EVB", "MODECTL", "SYSCFG",
            "IPEND", "VID", "IAD", "IEL", "IAHL", "CFGBASE", "DIAG",
            "REV", "PCYCLELO", "PCYCLEHI", "ISDBST", "ISDBCFG0",
            "ISDBCFG1", "BRKPTPC0", "BRKPTCFG0", "BRKPTPC1", "BRKPTCFG1",
            "ISDBMBXIN", "ISDBMBXOUT", "ISDBEN", "ISDBGPR", "PMUCNT0",
            "PMUCNT1", "PMUCNT2", "PMUCNT3", "PMUEVTCFG", "PMUCFG"],
    "SS": ["SGP"],
}

REGISTER_FIELDS = {
    "USR": [
        ("PFA", 1),
        ("FPINEE", 1),
        ("FPUNFE", 1),
        ("FPOVFE", 1),
        ("FPDBZE", 1),
        ("FPINVE", 1),
        ("FPRND", 2),
        ("HFI", 2),
        ("HFD", 2),
        ("PCMME", 1),
        ("PCGME", 1),
        ("PCUME", 1),
        ("LPCFG", 2),
        ("FPINPF", 1),
        ("FPUNFF", 1),
        ("FPOVFF", 1),
        ("FPDBZF", 1),
        ("FPINVF", 1),
        ("OVF", 1),
    ],
    "SYSCFG": [
        ("TLBLOCK", 1),
        ("K0LOCK", 1),
    ]
}

class Mnemonic:
    OPERATORS =  [
        ("+=", "acc"),
        ("-=", "nac"),
        ("&=", "aac"),
        ("|=", "oac"),
        ("^=", "xac"),
        ("++", "inc"),
        ("--", "dec"),
        ("==", "eq"),
        ("!=", "ne"),
        (">=", "sup"),
        ("<=", "inf"),
        ("!", "not"),
        ("~", "neg"),
        ("*", "cnj"),
        ("<<", "sft"),
        (">>", "rsf"),
    ]
    CHARACTERS = " ().,;:[]#+-="

    @staticmethod
    def normalize(syntax):
        # Normalize registers
        syntax = re.sub(r"([RNPMCSG])[uxevtsdy]{2}", r"_\1\1_", syntax)
        syntax = re.sub(r"([RNPMCSG])[uxevtsdy]\.L", r"_\1l_", syntax)
        syntax = re.sub(r"([RNPMCSG])[uxevtsdy]\.H", r"_\1h_", syntax)
        syntax = re.sub(r"([RNPMCSG])[uxevtsdy]", r"_\1_", syntax)

        # Normalize immediates
        def upper_repl(match):
            return "_{}_".format(match.group(1).upper())
        syntax = re.sub(r"#([uSsmrU])[123456789]:(0|1|2|3|31)", upper_repl, syntax)
        syntax = re.sub(r"#([uSsmrU])[123456789]", upper_repl, syntax)
        syntax = re.sub(r"-(\d+)", r"m\1", syntax)

        # Normalize operators
        for pattern, replace in Mnemonic.OPERATORS:
            syntax = syntax.replace(pattern, replace)

        # Normalize characters
        for char in Mnemonic.CHARACTERS:
            syntax = syntax.replace(char, "_")

        # Prepend the Q6 suffix
        syntax = "Q6_{}".format(syntax)

        # Remove extra underscores
        while "__" in syntax:
            syntax = syntax.replace("__", "_")
        syntax = syntax.strip("_")
        return syntax

    def __init__(self, syntax):
        self.syntax = syntax
        self.mnemonic = Mnemonic.normalize(syntax)

        # Sanity check
        charset = string.ascii_letters + string.digits + "_"
        assert all([c in charset for c in self.mnemonic])

    def __str__(self):
        return self.mnemonic

class Register:
    def __init__(self, token, ranges):
        self.token = token
        self.ranges = ranges

class Immediate:
    def __init__(self, token, length, shift, ranges):
        self.token = token
        self.length = length
        self.shift = shift
        self.ranges = ranges

class Encoding:
    def __init__(self, syntax, encoding):
        self.encoding = encoding[::-1]
        # Sanity check
        assert len(encoding) == 32

        registers, immediates = self.parse_syntax(syntax)
        # Sanity check
        self.characters = [l for l in set(encoding) if l not in "-01PN"]
        assert len(self.characters) == len(registers) + len(immediates)

        self.fixed_bits = []
        self.find_fixed_bits()
        self.registers = []
        self.match_registers(registers)
        self.immediates = []
        self.match_immediates(immediates)
        self.positions = []
        self.order_operands(syntax)

    @staticmethod
    def calc_ranges(indexes):
        ranges = []
        for index in indexes:
            if not ranges:
                ranges.append((index, index))
            else:
                last_range = ranges[-1]
                if last_range[1] == index - 1:
                    ranges[-1] = last_range[0], index
                else:
                    ranges.append((index, index))
        return ranges

    def parse_syntax(self, syntax):
        # Extract registers from syntax
        registers = []
        for match in re.finditer(r"[A-Z][a-z][a-z]?", syntax):
            register = match.group(0)
            if register not in registers:
                registers.append(register)

        # Extract immediates from syntax
        immediates = []
        for match in re.finditer(r"#[a-zA-Z][0-9]+(:[0-9]+)?", syntax):
            immediate = match.group(0)
            if immediate not in immediates:
                immediates.append(immediate)

        return registers, immediates

    def find_fixed_bits(self):
        fix_index = [i for i, char in enumerate(self.encoding) if char in "01"]
        fix_ranges = Encoding.calc_ranges(fix_index)
        self.fixed_bits = [(fix_beg, fix_end, self.encoding[fix_beg:fix_end + 1])
                           for fix_beg, fix_end in fix_ranges]

    def match_registers(self, registers):
        # Match registers from syntax with encoding
        for register in registers:
            reg_type = register[0]
            reg_char = register[1]

            # Sanity check
            assert reg_type in "RCGPMNS"
            assert reg_char in self.characters

            reg_index = [i for i, char in enumerate(self.encoding) if char == reg_char]
            reg_ranges = Encoding.calc_ranges(reg_index)

            # Sanity check
            assert len(reg_ranges) == 1
            reg_beg, reg_end = reg_ranges[0]
            reg_size = reg_end - reg_beg + 1

            register = Register(register, reg_ranges)
            self.registers.append(register)

    def match_immediates(self, immediates):
        # Match immediates from syntax with encoding
        for immediate in immediates:
            imm_type = immediate[1]
            if imm_type.lower() == imm_type:
                imm_char = "i"
            else:
                imm_char = "I"
            # Sanity check
            assert imm_type in "sSuUrR"
            assert imm_char in self.characters

            imm_index = [i for i, char in enumerate(self.encoding) if char == imm_char]
            imm_ranges = Encoding.calc_ranges(imm_index)
            # Sanity check
            assert len(imm_ranges) > 0

            imm_size = 0
            for imm_beg, imm_end in imm_ranges:
                imm_size += imm_end - imm_beg + 1

            # Extract shift is present
            if ":" in immediate:
                imm_length, imm_shift = immediate[2:].split(":")
            else:
                imm_length, imm_shift = immediate[2:], "0"
            imm_length, imm_shift = int(imm_length), int(imm_shift)

            # Sanity check
            assert imm_size == imm_length

            token = immediate.replace("#", "").split(":")[0]
            immediate = Immediate(token, imm_length, imm_shift, imm_ranges)
            self.immediates.append(immediate)

    def order_operands(self, syntax):
        for register in self.registers:
            position = syntax.index(register.token)
            self.positions.append((position, register.token))
        for immediate in self.immediates:
            position = syntax.index(immediate.token)
            self.positions.append((position, immediate.token))
        self.positions = [token for start, token in sorted(self.positions)]

class Type:
    pass

class Void(Type):
    def __eq__(self, other):
        return isinstance(other, Void)

    def __repr__(self):
        return "Void()"

class Integer(Type):
    @staticmethod
    def compare_length(this, other):
        return this == 0 or other == 0 or this == other

    @staticmethod
    def compare_signed(this, other):
        return this is None or other is None or this == other

    def __init__(self, length, signed):
        self.length = length
        self.signed = signed

    def __eq__(self, other):
        return isinstance(other, Integer) \
                and self.length == other.length \
                and self.signed == other.signed

    def __repr__(self):
        length = "??" if self.length == 0 else str(self.length)
        signed = "??" if self.signed is None else str(self.signed)
        return "Integer({}, {})".format(length, signed)

class Pointer(Type):
    def __init__(self, space, pointed):
        self.space = space
        self.pointed = pointed

    def __eq__(self, other):
        return isinstance(other, Pointer) \
                and self.space == other.space \
                and self.pointed == other.pointed

    def __repr__(self):
        return "Pointer({}, {!r})".format(self.space, self.pointed)

class Scope:
    def __init__(self, parent=None):
        self.parent = parent
        self.lines = []
        self.mapping = {}
        self.variables = {}

    def add_mapping(self, old_name, new_name):
        if old_name in self.mapping:
            assert self.mapping[old_name] == new_name
            return False
        self.mapping[old_name] = new_name
        return True

    def get_mapping(self, name):
        if name in self.mapping:
            name = self.mapping[name]
            return self.get_mapping(name)

        if self.parent:
            return self.parent.get_mapping(name)
        return name

    def add_variable(self, name, type):
        if name in self.variables:
            assert self.variables[name] == type
            return False
        self.variables[name] = type
        return True

    def get_variable(self, name):
        if name in self.variables:
            return self.variables[name]

        if self.parent:
            return self.parent.get_variable(name)
        return None

    def del_variable(self, name):
        if name in self.variables:
            self.variables.pop(name)
            return True

        if self.parent:
            return self.parent.del_variable(name)
        return False

    def decl_variable(self, name, type, expr=None):
        if not self.add_variable(name, type):
            return

        if isinstance(type, Integer):
            if type.length > 0:
                length = type.length
            else:
                type.length = length = 32
        elif isinstance(type, Pointer):
            length = 32
        else:
            assert False
        assert length % 8 == 0

        init = ""
        if expr is not None:
            init = " = {}".format(expr.print(self))
        self.lines.append("local {}:{}{};".format(name, length // 8, init))

    def print(self, node):
        line = node.print(self)
        if not line:
            return
        if not line.endswith(";"):
            line = line + ";"

        if isinstance(node.type, Void):
            self.lines.append(line)
        #else:
        #    print("Ignoring statement \"{}\"".format(line), file=sys.stderr)

    def show(self, ident=0, buf=sys.stdout):
        lead = " " * (ident * 4)
        print(lead + "Scope #{}:".format(ident), file=buf)
        print(lead +  "  Lines:", file=buf)
        for line in self.lines:
            print(lead + "   - {}".format(line), file=buf)
        print(lead + "  Mapping:", file=buf)
        for old_name, new_name in self.mapping.items():
            print(lead + "   - {} -> {}".format(old_name, new_name), file=buf)
        print(lead + "  Variables:", file=buf)
        for name, type in self.variables.items():
            print(lead + "   - {} -> {!r}".format(name, type), file=buf)

        if self.parent:
            self.parent.show(ident + 1, buf=buf)

class NodeException(Exception):
    def __init__(self, node, frame, msg):
        super().__init__(msg)
        self.node = node
        self.frame = frame

class Node:
    @staticmethod
    def labelify(node):
        charset = string.ascii_letters + string.digits + "_"
        label = [c if c in charset else "_" for c in str(node)]
        return re.sub(r"_+", r"_", "".join(label)).strip("_")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "type" in self.__slots__:
            slots = list(self.__slots__)
            slots[slots.index("type")] = "orig_type"
            self.__slots__ = tuple(slots)
            self.orig_type = self.type
        self.type = None

        # Ensure eval sets type
        old_eval = self.eval
        def new_eval(scope):
            try:
                node = old_eval(scope)
            except Exception as e:
                if isinstance(e, NodeException):
                    raise e
                frame = e.__traceback__.tb_next.tb_frame
                raise NodeException(self, frame, str(e))
            self.check(node is not None)
            self.check(node.type is not None)
            return node
        self.eval = new_eval

    def check(self, cond, msg=None):
        if not cond:
            frame = inspect.currentframe().f_back
            raise NodeException(self, frame, msg)

    def eval(self, scope):
        raise self.check(False, "eval() not implemented")

    def print(self, scope):
        raise self.check(False, "print() not implemented")

    def __repr__(self):
        attrs = ["{!r}".format(self.type)]
        for attr in self.__slots__[:-2]:
            attrs.append("{}={!r}".format(attr, getattr(self, attr)))
        name = self.__class__.__name__
        return "{}({})".format(name, ", ".join(attrs))

    def is_ident(self):
        return isinstance(self, ID)

    def get_name(self):
        self.check(self.is_ident())
        return self.name

    def is_const(self):
        return isinstance(self, Constant)

    def get_value(self):
        self.check(self.is_const())
        return int(self.value, 0)

    def returns_value(self):
        self.check(self.type is not None)
        return not isinstance(self.type, Void)

    def is_assignable(self):
        return False

    def resize(self, scope, length):
        self.check(isinstance(self.type, Integer))
        if self.type.length == 0:
            self.type.length = length
        if self.type.length == length:
            return self

        if self.type.length < length:
            self.check(self.returns_value())
            self.check(length % 8 == 0)
            name = ID("sxt" if self.type.signed else "zxt")
            old_length = Constant("int", str(self.type.length))
            new_length = Constant("int", str(length))
            args = ExprList([old_length, new_length, self])
            node = FuncCall(name, args)
            node.eval(scope)
            return node

        else:
            self.check(self.is_assignable())
            self.check(length % 8 == 0)
            node = UnaryOp(":{}".format(length // 8), self)
            node.eval(scope)
            return node

class ArrayDecl(Node, c_ast.ArrayDecl):
    pass

class ArrayRef(Node, c_ast.ArrayRef):
    def eval(self, scope):
        self.name = self.name.eval(scope)
        self.check(self.name.is_assignable())
        self.subscript = self.subscript.eval(scope)
        self.check(self.subscript.returns_value())

        if isinstance(self.name.type, Pointer):
            self.check(self.subscript.is_const() or \
                (self.subscript.type.length == 32 \
                 and self.subscript.type.signed is False))
            self.type = self.name.type.pointed
            return self

        if self.name.is_ident():
            self.check(self.subscript.is_const())
            index = self.subscript.get_value()
            self.check(self.name.type.length > index)
            self.type = Integer(1, False)
            return self

        self.check(False)

    def print(self, scope):
        if isinstance(self.name.type, Pointer):
            array = self.name.print(scope)
            index = self.subscript.print(scope)
            space = self.name.type.space
            length = self.type.length // 8
            expr = "({} + {} * {})".format(array, length, index)
            return "*[{}]:{} {}".format(space, length, expr)

        if self.name.is_ident() and self.name.type.length > 0:
            array = self.name.print(scope)
            index = self.subscript.print(scope)
            return "{}[{}, 1]".format(array, index)

        self.check(False)

    def is_assignable(self):
        return True

class Assignment(Node, c_ast.Assignment):
    def eval(self, scope):
        if self.op == "=":
            self.lvalue = self.lvalue.eval(scope)
            self.check(self.lvalue.is_assignable())
            self.rvalue = self.rvalue.eval(scope)
            self.check(self.rvalue.returns_value())
            if self.lvalue.type.length == 0:
                self.lvalue = self.lvalue.resize(scope, self.rvalue.type.length)
            else:
                self.rvalue = self.rvalue.resize(scope, self.lvalue.type.length)
            self.type = Void()
            return self

        elif self.op in ["+=", "-=", "*=", "/=", "&=", "|=", "^="]:
            rvalue = BinaryOp(self.op[0], self.lvalue, self.rvalue)
            node = Assignment("=", self.lvalue, rvalue)
            return node.eval(scope)

        else:
            self.check(False)

    def print(self, scope):
        scope.lines.append("{} = {};".format(
            self.lvalue.print(scope), self.rvalue.print(scope)))
        return ""

class BinaryOp(Node, c_ast.BinaryOp):
    ARITHMETIC = ["+", "-", "*", "/", "<<", ">>", "&", "|", "^"]
    COMPARISON = ["==", "!=", "<", ">", "<=", ">=", "s<", "s>", "s<=", "s>="]

    def eval(self, scope):
        self.check(self.op in BinaryOp.ARITHMETIC + BinaryOp.COMPARISON)
        self.left = self.left.eval(scope)
        self.check(self.left.returns_value())
        left_type = self.left.type
        self.right = self.right.eval(scope)
        self.check(self.right.returns_value())
        right_type = self.right.type

        if self.op in [">>", "<<"]:
            self.type = left_type
            return self

        if left_type.length < right_type.length:
            self.left = self.left.resize(scope, right_type.length)

        if right_type.length < left_type.length:
            self.right = self.right.resize(scope, left_type.length)

        if self.op in BinaryOp.COMPARISON:
            if self.op in ["<", ">", "<=", ">="]:
                if left_type.signed == False or right_type.signed == False:
                    self.check(Integer.compare_signed(left_type.signed, right_type.signed))

                elif left_type.signed == True or right_type.signed == True:
                    self.check(Integer.compare_signed(left_type.signed, right_type.signed))
                    self.op = "s{}".format(self.op)

                elif left_type.signed is None and right_type.signed is None:
                    #print("Assuming comparison is signed for {}".format(self.print(scope)), file=sys.stderr)
                    self.op = "s{}".format(self.op)

                else:
                    self.check(False)

            self.type = Integer(1, False)
        else:
            self.type = left_type
        return self

    def print(self, scope):
        return "({} {} {})".format(self.left.print(scope),
                                   self.op,
                                   self.right.print(scope))

class Break(Node, c_ast.Break):
    pass

class Case(Node, c_ast.Case):
    pass

class Cast(Node, c_ast.Cast):
    pass

class Compound(Node, c_ast.Compound):
    def eval(self, scope):
        self.block_items = (self.block_items or [])
        if len(self.block_items) == 0:
            self.type = Void()
            return self

        block_items = []
        for child in self.block_items:
            child = child.eval(scope)
            block_items.append(child)
        self.block_items = block_items
        self.type = self.block_items[-1].type
        return self

    def print(self, scope):
        if len(self.block_items) == 0:
            return ""

        for child in self.block_items[:-1]:
            scope.print(child)
        return self.block_items[-1].print(scope)

    def is_assignable(self):
        if len(self.block_items) == 0:
            return super().is_assignable()
        return self.block_items[-1].is_assignable()

class CompoundLiteral(Node, c_ast.CompoundLiteral):
    pass

class Constant(Node, c_ast.Constant):
    def eval(self, scope):
        self.check(self.orig_type == 'int')
        self.type = Integer(0, None)
        return self

    def print(self, scope):
        return self.value

class Continue(Node, c_ast.Continue):
    pass

class Decl(Node, c_ast.Decl):
    pass

class DeclList(Node, c_ast.DeclList):
    pass

class Default(Node, c_ast.Default):
    pass

class DoWhile(Node, c_ast.DoWhile):
    pass

class EllipsisParam(Node, c_ast.EllipsisParam):
    pass

class EmptyStatement(Node, c_ast.EmptyStatement):
    pass

class Enum(Node, c_ast.Enum):
    pass

class Enumerator(Node, c_ast.Enumerator):
    pass

class EnumeratorList(Node, c_ast.EnumeratorList):
    pass

class ExprList(Node, c_ast.ExprList):
    def eval(self, scope):
        exprs = []
        for child in self.exprs:
            child = child.eval(scope)
            self.check(child.returns_value())
            exprs.append(child)
        self.exprs = exprs
        self.type = Void()
        return self

    def print(self, scope):
        exprs = []
        for child in self.exprs:
            exprs.append(child.print(scope))
        return ", ".join(exprs)

class FileAST(Node, c_ast.FileAST):
    pass

class For(Node, c_ast.For):
    def eval(self, scope):
        # self.init = self.init.eval(scope)
        self.check(isinstance(self.init, Assignment))
        self.check(self.init.lvalue.is_ident())
        self.loop_var = self.init.lvalue
        self.check(self.init.rvalue.is_const())
        self.init_val = self.init.rvalue

        # self.cond = self.cond.eval(scope)
        self.check(isinstance(self.cond, BinaryOp))
        self.check(self.cond.left.is_ident())
        self.check(self.cond.left.get_name() == self.loop_var.get_name())
        self.check(self.cond.right.is_const())
        self.cond_val = self.cond.right

        # self.next = self.next.eval(scope)
        self.check(isinstance(self.next, UnaryOp))
        self.check(self.next.op == "p++")
        self.check(self.next.expr.is_ident())
        self.check(self.next.expr.get_name() == self.loop_var.get_name())
        self.step_val = Constant("int", "1").eval(scope)

        # Add the loop variable
        scope.add_variable(self.loop_var.get_name(), Integer(32, False))

        self.stmt_scope = Scope(scope)
        self.stmt = self.stmt.eval(self.stmt_scope)
        self.check(not self.stmt.returns_value())

        # Remove the loop variable
        scope.del_variable(self.loop_var.get_name())

        self.type = Void()
        return self

    def print(self, scope):
        loop_var = self.loop_var.print(scope)
        init_val = self.init_val.print(scope)
        cond_val = self.cond_val.print(scope)
        step_val = self.step_val.print(scope)
        label = "for_{}".format(loop_var)
        self.stmt_scope.print(self.stmt)

        scope.lines.append("local {}:4 = {};".format(loop_var, init_val))
        scope.lines.append("<{}>".format(label))
        for line in self.stmt_scope.lines:
            scope.lines.append(line)
        scope.lines.append("{} = {} + {};".format(loop_var, loop_var, step_val))
        scope.lines.append("if ({} < {}) goto <{}>;".format(loop_var, cond_val, label))
        return ""

class FuncCall(Node, c_ast.FuncCall):
    def eval(self, scope):
        self.name = self.name.eval(scope)
        if self.name.get_name() == "apply_extension":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 1)
            self.check(self.args.exprs[0].is_assignable())
            return self.args.exprs[0]

        elif self.name.get_name() in ["sat", "usat"]:
            # TODO: Handle value saturation
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 2)
            return self.args.exprs[1]

        elif self.name.get_name() in ["sxt", "zxt"]:
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 3)

            self.check(self.args.exprs[0].is_const())
            old_length = self.args.exprs[0].get_value()
            self.check(self.args.exprs[1].is_const())
            new_length = self.args.exprs[1].get_value()
            self.check(old_length < new_length)

            signed = self.name.get_name() == "sxt"
            expr = self.args.exprs[2]
            self.check(Integer.compare_signed(expr.type.signed, signed))

            self.name.name = self.name.name.replace("xt", "ext")
            self.args.exprs = [expr.resize(scope, old_length)]
            self.type = Integer(new_length, signed)
            return self

        elif self.name.get_name() == "newSuffix":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 1)
            self.check(self.args.exprs[0].is_assignable())
            # FIXME: Workaround for new-values
            arg = self.args.exprs[0]
            token = arg.print(scope)
            if re.match(r"N[s-v]_\d+\d+", token):
                arg_name = "arg_{}".format(Node.labelify(token))
                scope.decl_variable(arg_name, arg.type, arg)
                self.args.exprs[0] = ID(arg_name).eval(scope)
            self.type = self.args.exprs[0].type
            return self

        elif self.name.get_name() == "nextPacket":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 0)
            self.type = Integer(32, False)
            return self

        elif self.name.get_name() == "constExtend":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 0)
            self.type = Integer(0, None)
            return self

        elif self.name.get_name() == "circAdd":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 3)
            # FIXME: Workaround for immediates
            arg = self.args.exprs[1]
            token = arg.print(scope)
            if re.match(r"[sSuUrR]\d+", token):
                arg_name = "arg_{}".format(Node.labelify(token))
                scope.decl_variable(arg_name, arg.type, arg)
                self.args.exprs[1] = ID(arg_name).eval(scope)
            self.type = self.args.exprs[0].type
            return self

        elif self.name.get_name() == "bitsRev":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 1)
            self.check(self.args.exprs[0].returns_value())
            self.type = self.args.exprs[0].type
            return self

        elif self.name.get_name() == "frameUnscramble":
            self.args = self.args.eval(scope)
            self.check(len(self.args.exprs) == 1)
            self.check(self.args.exprs[0].returns_value())
            self.check(self.args.exprs[0].type.length == 64)
            self.check(self.args.exprs[0].type.signed == False)
            self.type = self.args.exprs[0].type
            return self

        else:
            self.check(False)

    def print(self, scope):
        return "{}({})".format(self.name.print(scope),
                               self.args.print(scope))

class FuncDecl(Node, c_ast.FuncDecl):
    pass

class FuncDef(Node, c_ast.FuncDef):
    pass

class Goto(Node, c_ast.Goto):
    pass

class ID(Node, c_ast.ID):
    IGNORED_FUNCTIONS = ["PREDUSE_TIMING", "NOP"]
    BUILTIN_FUNCTIONS = ["apply_extension", "sat", "usat", "sxt", "zxt"]
    PCODEOP_FUNCTIONS = ["newSuffix", "nextPacket", "constExtend",
                         "circAdd", "bitsRev", "frameUnscramble"]
    SUBPIECE_KEYWORDS = ["b", "ub", "h", "uh", "w", "uw", "new"]

    def eval(self, scope):
        if self.name in ID.IGNORED_FUNCTIONS:
            return Compound([]).eval(scope)

        if self.name in ID.BUILTIN_FUNCTIONS \
                or self.name in ID.PCODEOP_FUNCTIONS \
                or self.name in ID.SUBPIECE_KEYWORDS:
            self.type = Void()
            return self

        self.name = scope.get_mapping(self.name)
        self.type = scope.get_variable(self.name)
        if self.type is None:
            if self.name in ["tmp", "EA"]:
                self.type = Integer(32, False)
                scope.decl_variable(self.name, self.type)
                return self

            if self.name in ["MuV", "tmpV"]:
                return ID(self.name[:-1]).eval(scope)

            if self.name == "I":
                name = scope.get_mapping("Mu")
                self.type = Integer(32, False)
                line = "local I:4 = ((({} >> 28) & 0xf) << 7) | (({} >> 17) & 0x7f);"
                scope.lines.append(line.format(name, name))
                scope.add_variable("I", self.type)
                return self

            if self.name == "NPC":
                node = FuncCall(ID("nextPacket"), ExprList([]))
                return node.eval(scope)

            if self.name == "Constant_extended":
                node = FuncCall(ID("constExtend"), ExprList([]))
                return node.eval(scope)

            if self.name == "circ_add":
                return ID("circAdd").eval(scope)

            if self.name == "brev":
                return ID("bitsRev").eval(scope)

            if self.name == "frame_unscramble":
                return ID("frameUnscramble").eval(scope)

            # Check if it is a register name
            for reg_type, tokens in REGISTER_NAMES.items():
                if self.name in tokens:
                    length = REGISTER_SIZES[reg_type]
                    self.type = Integer(length, False)
                    scope.add_variable(self.name, self.type)
                    return self

            # Check if it is a register alias
            for reg_type, tokens in REGISTER_ALIASES.items():
                if self.name in tokens:
                    length = REGISTER_SIZES[reg_type]
                    old_name = self.name
                    self.name = "$({})".format(self.name)
                    self.type = Integer(length, False)
                    scope.add_mapping(old_name, self.name)
                    scope.add_variable(self.name, self.type)
                    return self

            # Check if it is a register field
            for reg_name, fields in REGISTER_FIELDS.items():
                for field, length in fields:
                    if field == self.name:
                        old_name = self.name
                        self.name = "$({})".format(self.name)
                        self.type = Integer(length, False)
                        scope.add_mapping(old_name, self.name)
                        scope.add_variable(self.name, self.type)
                        return self

            self.check(False, "Unknown identifier")
        return self

    def print(self, scope):
        return self.name

    def is_assignable(self):
        return self.returns_value()

class IdentifierType(Node, c_ast.IdentifierType):
    pass

class If(Node, c_ast.If):
    def eval(self, scope):
        self.cond = self.cond.eval(scope)
        self.check(self.cond.returns_value())

        if self.cond.type.length == 0:
            arg_name = "arg_{}".format(Node.labelify(self.cond.print(scope)))
            arg_type = Integer(32, False)
            scope.decl_variable(arg_name, arg_type, self.cond)
            self.cond = ID(arg_name).eval(scope)

        if self.cond.type.length > 1:
            node = BinaryOp("!=", self.cond, Constant("int", "0"))
            self.cond = node.eval(scope)

        self.iftrue_scope = Scope(scope)
        self.iftrue = self.iftrue.eval(self.iftrue_scope)
        self.check(not self.iftrue.returns_value())

        if self.iffalse is not None:
            self.iffalse_scope = Scope(scope)
            self.iffalse = self.iffalse.eval(self.iffalse_scope)
            self.check(not self.iffalse.returns_value())

        self.type = Void()
        return self

    def print(self, scope):
        cond = self.cond.print(scope)
        label = "if_{}".format(Node.labelify(cond))

        scope.lines.append("if ({}) goto <{}>;".format(cond, label))
        if self.iffalse is not None:
            self.iffalse_scope.print(self.iffalse)
            for line in self.iffalse_scope.lines:
                scope.lines.append(line)
        scope.lines.append("goto <{}>;".format("end" + label))
        scope.lines.append("<{}>".format(label))
        self.iftrue_scope.print(self.iftrue)
        for line in self.iftrue_scope.lines:
            scope.lines.append(line)
        scope.lines.append("<{}>".format("end" + label))
        return ""

class InitList(Node, c_ast.InitList):
    pass

class Label(Node, c_ast.Label):
    pass

class NamedInitializer(Node, c_ast.NamedInitializer):
    pass

class ParamList(Node, c_ast.ParamList):
    pass

class PtrDecl(Node, c_ast.PtrDecl):
    pass

class Return(Node, c_ast.Return):
    pass

class Struct(Node, c_ast.Struct):
    pass

class StructRef(Node, c_ast.StructRef):
    def eval(self, scope):
        self.check(self.orig_type == ".")
        self.name = self.name.eval(scope)
        self.field = self.field.eval(scope)

        if self.name.is_ident() and self.name.get_name() == "$(USR)":
            return self.field

        field = self.field.get_name()
        if field == "new":
            new_name = "new_{}".format(field)
            new_type = self.name.type
            new_expr = FuncCall(ID("newSuffix"), ExprList([self.name]))
            new_expr = new_expr.eval(scope)
            scope.decl_variable(new_name, new_type, new_expr)
            return ID(new_name).eval(scope)

        if field[-1] == "b":
            length = 8
        elif field[-1] == "h":
            length = 16
        elif field[-1] == "w":
            length = 32
        else:
            self.check(False, "Unknown modifier")
        signed = field[0] != "u"

        self.check(self.name.is_assignable())
        self.check(self.name.type.length >= length)

        ref_name = "{}_{}".format(self.name.get_name(), field)
        space = "register"
        if not re.match(r"[A-Z][a-z]{1,2}_\d+_\d+", self.name.get_name()):
            space = "ram"
        ref_type = Pointer(space, Integer(length, signed))
        ref_expr = UnaryOp("&", self.name).eval(scope)
        scope.decl_variable(ref_name, ref_type, ref_expr)
        return ID(ref_name).eval(scope)

    def print(self, scope):
        self.check(False)

class Switch(Node, c_ast.Switch):
    pass

class TernaryOp(Node, c_ast.TernaryOp):
    def eval(self, scope):
        self.cond = self.cond.eval(scope)
        self.iftrue = self.iftrue.eval(scope)
        self.iffalse = self.iffalse.eval(scope)

        if not self.iftrue.returns_value() \
                and not self.iffalse.returns_value():
            node = If(self.cond, self.iftrue, self.iffalse)
            node.eval(scope)
            return node

        elif self.iftrue.returns_value() \
                and self.iffalse.returns_value():
            self.check(Integer.compare_length(self.iftrue.type.length, self.iffalse.type.length))
            self.check(Integer.compare_signed(self.iftrue.type.signed, self.iffalse.type.signed))
            cond = self.cond.print(scope)
            res_name = "res_{}".format(Node.labelify(cond))
            res_type = self.iftrue.type
            scope.decl_variable(res_name, res_type)
            result = ID(res_name)

            iftrue = Assignment("=", result, self.iftrue)
            iffalse = Assignment("=", result, self.iffalse)
            node = If(self.cond, iftrue, iffalse)
            return Compound([node, result]).eval(scope)

        self.check(False)

    def print(self, scope):
        self.check(False)

class TypeDecl(Node, c_ast.TypeDecl):
    pass

class Typedef(Node, c_ast.Typedef):
    pass

class Typename(Node, c_ast.Typename):
    pass

class UnaryOp(Node, c_ast.UnaryOp):
    def eval(self, scope):
        self.expr = self.expr.eval(scope)

        if self.op.startswith(":"):
            self.check(self.expr.returns_value())
            self.type = self.expr.type
            self.type.length = int(self.op[1:]) * 8

        elif self.op == "&":
            self.check(self.expr.is_assignable())
            self.check(self.expr.is_ident())
            space = "register"
            if not re.match(r"[A-Z][a-z]{1,2}_\d+_\d+", self.expr.get_name()):
                space = "ram"
            self.type = Pointer(space, self.expr.type)

        elif self.op == "*":
            self.check(self.expr.is_ident())
            self.check(self.expr.get_name() == "EA")
            self.type = Integer(0, None)
            return self

        elif self.op in ["+", "-"]:
            self.check(self.expr.returns_value())
            self.type = self.expr.type

        elif self.op == "~":
            self.check(self.expr.returns_value())
            if self.expr.is_const():
                cst_name = "cst_{}".format(self.expr.print(scope))
                cst_type = Integer(32, False)
                scope.decl_variable(cst_name, cst_type, self.expr)
                self.expr = ID(cst_name).eval(scope)
            self.type = self.expr.type

        elif self.op == "!":
            self.check(self.expr.returns_value())
            self.check(self.expr.type.length == 1)
            self.check(self.expr.type.signed == False)
            self.type = self.expr.type

        else:
            self.check(False)
        return self

    def print(self, scope):
        expr = self.expr.print(scope)
        if self.op.startswith(":"):
            return "{}{}".format(expr, self.op)
        elif self.op == "&":
            return "{}{}".format(self.op, expr)
        elif self.op == "*":
            self.check(self.type.length > 0)
            self.check(self.type.length % 8 == 0)
            return "*:{} {}".format(self.type.length // 8, expr)
        elif self.op in ["+", "-", "~", "!"]:
            return "({}{})".format(self.op, expr)

    def is_assignable(self):
        return self.op.startswith(":") or self.op == "*"

class Union(Node, c_ast.Union):
    pass

class While(Node, c_ast.While):
    pass

class Pragma(Node, c_ast.Pragma):
    pass

class Behavior:
    @staticmethod
    def convert_node(node):
        if isinstance(node, list):
            return [Behavior.convert_node(child) for child in node]
        elif not isinstance(node, c_ast.Node):
            return node

        # Convert arguments
        args = []
        for attr in node.__slots__[:-1]:
            args.append(Behavior.convert_node(getattr(node, attr)))

        # Create new instance
        node = node.__class__.__name__
        assert node in globals(), node
        return globals()[node](*args)

    def __init__(self, behavior):
        self.behavior = behavior
        # Remove comments
        behavior = "\n".join([line.split("//")[0] for line in behavior.split("\n")])
        text = "int main() {{\n{}\n}}".format(behavior)
        ast = cparser.parse(text, filename='<none>')
        self.nodes = Behavior.convert_node(ast.ext[0].body)

class Constructor:
    def __init__(self, syntax, encoding, behavior):
        self.mnemonic = Mnemonic(syntax)
        self.encoding = Encoding(syntax, encoding)
        self.behavior = Behavior(behavior)

        self.comments = []
        self.generate_comments()
        self.tokens = {}
        self.variables = {}

        self.display = []
        self.pattern = []
        self.actions = []
        self.generate_decoder()

        self.semantic = []
        self.generate_executor()

    def create_token(self, token, range, signed=False):
        if token in self.tokens:
            assert self.tokens[token] == (range, signed)
        else:
            self.tokens[token] = (range, signed)

    def generate_comments(self):
        self.comments.append("")
        self.comments.append(self.mnemonic.syntax)
        self.comments.append(self.encoding.encoding[::-1])
        self.comments.append("")
        for line in self.behavior.behavior.split("\n"):
            self.comments.append(line)
        self.comments.append("")

    def generate_decoder(self):
        for register in self.encoding.registers[::-1]:
            reg_beg, reg_end = register.ranges[0]
            token = "{}_{}_{}".format(register.token, reg_end, reg_beg)
            self.create_token(token, (reg_beg, reg_end))
            self.display.append(token)
            self.pattern.append(token)

        for immediate in self.encoding.immediates[::-1]:
            action = []
            imm_shift = immediate.shift

            for imm_beg, imm_end in immediate.ranges[::-1]:
                token = "{}_{}_{}".format(immediate.token, imm_end, imm_beg)
                self.create_token(token, (imm_beg, imm_end), token[0] in "sSrR")
                if immediate.token not in self.display:
                    self.display.append(immediate.token)
                self.pattern.append(token)

                # FIXME: There might be a bug in Sleigh
                #   [s8 = (s8_12_5 << 0);] is fine
                #   [s[s8 = s8_12_5;] throws java.lang.IndexOutOfBoundsException
                #
                #if imm_shift == 0:
                #    action.append(token)
                #else:
                action.append("({} << {})".format(token, imm_shift))
                imm_shift += imm_end - imm_beg + 1

            action = "{} = {};".format(immediate.token, " | ".join(action))
            self.actions.append(action)

        for fix_beg, fix_end, fixed_bits in self.encoding.fixed_bits[::-1]:
            token = "bits_{}_{}".format(fix_end, fix_beg)
            self.create_token(token, (fix_beg, fix_end))
            self.pattern.append("{}=0b{}".format(token, fixed_bits[::-1]))

        # Sort display according to syntax
        self.display.sort(key=lambda token: self.encoding.positions.index(token.split("_")[0]))
        self.pattern.sort(key=lambda token: int(token.split("_")[1], 10), reverse=True)

    def generate_executor(self):
        scope = Scope()

        # FIXME: Workaround for frames
        if "frame_unscramble(tmp)" in self.behavior.behavior:
            scope.decl_variable("tmp", Integer(64, False))

        for register in self.encoding.registers[::-1]:
            reg_beg, reg_end = register.ranges[0]
            reg_length = reg_end - reg_beg + 1
            token = "{}_{}_{}".format(register.token, reg_end, reg_beg)
            reg_type = register.token[0] * (len(register.token) - 1)
            reg_type = "r" if reg_type == "R" and reg_length == 4 else reg_type
            assert reg_type in REGISTER_SIZES, reg_type
            reg_length = REGISTER_SIZES[reg_type]
            if reg_type not in self.variables:
                self.variables[reg_type] = []
            self.variables[reg_type].append(token)
            scope.add_mapping(register.token, token)
            scope.add_variable(token, Integer(reg_length, None))

        for immediate in self.encoding.immediates[::-1]:
            token = immediate.token
            imm_signed = immediate.token[0] in "sSrR"
            scope.add_mapping("imm_{}".format(token[0]), token)
            scope.add_variable(immediate.token, Integer(32, imm_signed))

        try:
            self.behavior.nodes.eval(scope)
            scope.print(self.behavior.nodes)
            for line in scope.lines:
                if line:
                    self.semantic.append(line)
        except NodeException as e:
            print((" " + self.mnemonic.syntax + " ").center(80, "#"), file=sys.stderr)
            print(self.behavior.behavior, file=sys.stderr)
            print("-" * 80, file=sys.stderr)
            self.behavior.nodes.show(showcoord=True, buf=sys.stderr)
            print("-" * 80, file=sys.stderr)
            print("Node: {!r}".format(e.node), file=sys.stderr)
            if "scope" in e.frame.f_locals:
                e.frame.f_locals["scope"].show(buf=sys.stderr)
            print("-" * 80, file=sys.stderr)
            print("Message: {}".format(e), file=sys.stderr)
            for i, info in enumerate(inspect.getouterframes(e.frame)):
                if i == 3:
                    break
                print("File \"{}\", line {}, in {}".format(info.filename, info.lineno, info.function), file=sys.stderr)
                print("\n".join(info.code_context).strip("\n"), file=sys.stderr)
            print("Locals:", file=sys.stderr)
            for key, val in e.frame.f_locals.items():
                if key not in ["self", "scope"]:
                    print(" - {}: {!r}".format(key, val), file=sys.stderr)
            exit()

    def __str__(self):
        lines = []
        for comment in self.comments:
            lines.append("# {}".format(comment))
        display = ", ".join(self.display)
        pattern = " & ".join(self.pattern)
        actions = " ".join(self.actions)
        lines.append(":{} {}".format(self.mnemonic, display))
        if actions:
            lines.append("        is {}".format(pattern))
            lines.append("            [{}] {{".format(actions))
        else:
            lines.append("        is {} {{".format(pattern))
        for line in self.semantic:
            lines.append("    {}".format(line))
        lines.append("}")
        return "\n".join(lines)

def main(args):
    constructors = []
    dataset = json.load(args.input)
    if args.count:
        dataset = dataset[:args.count]
    for data in dataset:
        # Skip assembly mapped instructions
        if data[1] == "-" * 32:
            continue

        constructor = Constructor(*data)
        constructors.append(constructor)

    print("#")
    print("# This file was generated automatically")
    print("#")

    print("")
    print("define token encoding (32)")
    encodings = []
    variables = {}
    for constructor in constructors:
        for token in constructor.tokens:
            if token not in encodings:
                encodings.append(token)
                (tok_beg, tok_end), signed = constructor.tokens[token]
                signed = " signed" if signed else ""
                print("     {}=({},{}){}".format(token, tok_beg, tok_end, signed))
        for reg_type, tokens in constructor.variables.items():
            if reg_type not in variables:
                variables[reg_type] = []
            for token in tokens:
                if token not in variables[reg_type]:
                    variables[reg_type].append(token)
    print(";")

    for reg_type, tokens in variables.items():
        if reg_type == "N":
            print("")
            print("attach values [ {} ]".format(" ".join(tokens)))
            print("    [ 0 1 2 3 4 5 6 7 ]")
            print(";")
            continue

        assert reg_type in REGISTER_NAMES
        values = REGISTER_NAMES[reg_type]
        print("")
        print("attach variables [ {} ]".format(" ".join(tokens)))
        width = max([len(value) for value in values])
        for i in range(0, len(values), 8):
            prefix = "    [" if i == 0 else "     "
            suffix = "]" if i + 8 >= len(values) else ""
            print(prefix + " ".join(["{:{width}}".format(value, width=width) for value in values[i:i + 8]]) + suffix)
        print(";")

    print("")
    for pcodeop in ID.PCODEOP_FUNCTIONS:
        print("define pcodeop {};".format(pcodeop))

    for constructor in constructors:
        print("")
        print(constructor)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count", type=int)
    parser.add_argument("input", type=argparse.FileType('r'))
    main(parser.parse_args())

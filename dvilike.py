#!/usr/bin/python3

from construct import (Adapter, Anchor, Array, BitStruct, Byte,
                       Construct, ConstructError, Debugger, Embed,
                       Enum, Field, FieldError, Flag, GreedyRange, If,
                       MappingError, OptionalGreedyRange, Padding,
                       PascalString, Pass, Probe, Range, RepeatUntil,
                       Sequence, StaticField, String, Struct, Switch,
                       Terminator, Tunnel, SBInt8, SBInt16, SBInt32,
                       UBInt16, UBInt32, Value)
from construct.core import (_read_stream, _write_stream)
from construct.lib import Container, ListContainer

# Debugging
import pdb
import pympler.asizeof
import pympler.classtracker

# Other
import sys
import io
import collections
import abc
import itertools
import functools
# import collections.abc


# The high-high level architecture of this program works like:

# DVILikeProcessor parses a file to create a representation in Python.

# DVILikeMachine transforms the representation into another form, like
# hypothetically text (DVIasm, dvitype), an SVG file (dvisvgm), or
# a virtual hypertext font.

# Another program prints the internal representation to a file.

# This chain can also be reversed to make the various TeX files.


# http://hroch486.icpf.cas.cz/xetex-test/

class IntField(StaticField):
    """Construct to read and write arbitrary-length binary integers.
    
    This class is adapted from FormatField in construct/core.py but
    uses the Python3 methods int.from_bytes and int.to_bytes to
    convert from and to bytes rather than the struct module.  I
    created it for two reasons: a Construct that could take an integer
    argument to process integers of that many bytes makes the code to
    define the opcode quadruplets that contain integer parameters of
    one to four bytes much simpler, and it reads three-byte integers
    more easily and faster.  If I'd used struct, I would have had to
    write code to convert a number of bytes into the correct struct
    format code to solve the first problem (the right solution would
    have been to do this for all integers) and to convert two-byte and
    one-byte integers into signed and unsigned three-byte integers to
    solve the second.

    Struct is faster than int.from_bytes and int.to_bytes, but for
    this application, the speed difference isn't significant enough to
    justify complicating the code, more like a factor of two rather
    than a factor of 10 to implement unpacking in pure Python.
    Additionally, for three-byte integers, having to convert from a
    one- and two-byte integer in Python would eat any speed gains from
    using struct anyways.

    Attributes:
        name: A string, the name of the Construct.
        length: An int, length of the integer in bytes.
        byteorder: 'big' or 'little' for big- or little-endian
            integers, as for int.from_bytes and int.to_bytes.
        signed: Boolean for signed or unsigned integers, as for
            int.from_bytes and int.to_bytes.
    """

    __slots__ = ('byteorder', 'signed')

    def __init__(self, name, length, byteorder, signed):
        """ Sets the parameters for the int methods and calls the parent init.
        """
        if byteorder not in ("big", "little"):
            raise ValueError("Byteorder must be 'big' or 'little' for big- or little-endian numbers.", byteorder)
        if not isinstance(signed, bool):
            raise ValueError("Signed must be true or false.")
        self.byteorder = byteorder
        self.signed = signed
        StaticField.__init__(self, name, length)

    def _parse(self, stream, context):
        """ Create a container representing an integer from binary data.
        """
        try:
            return int.from_bytes(_read_stream(stream, self.length), self.byteorder, signed = self.signed)
        except Exception:
            raise FieldError(sys.exc_info()[1])

    def _build(self, obj, stream, context):
        """ Turn a container into a binary data representation of an integer.
        """
        try:
            _write_stream(stream, self.length, obj.to_bytes(self.length, self.byteorder, signed = self.signed))
        except Exception:
            raise FieldError(sys.exc_info()[1])


def UBInt24(name):
    """Unsigned, big endian 24-bit integer"""
    return IntField(name, 3, 'big', False)

def SBInt24(name):
    """Signed, big endian 24-bit integer"""
    return IntField(name, 3, 'big', True)


class FastSwitch(Switch):
    """Import note: since this class inherits slots from Switch, there's
    no way for me to lose the keyfunc or include_key attributes.
    Since it will only cost me a tiny amount of additional memory, I
    define a new attribute to hold the key for the context dictionary
    and leave keyfunc and include_key empty.
    """

    __slots__ = ('key')

    def __init__(self, name, key, cases, default = Switch.NoDefault):
        Construct.__init__(self, name)
        self._inherit_flags(*cases.values())
        self._set_flag(self.FLAG_DYNAMIC)
        self.cases = cases
        self.key = key
        self.default = default
    def _parse(self, stream, context):
        case = self.cases.get(context[self.key], self.default)
        return case._parse(stream, context) 
    def _build(self, obj, stream, context):
        case = self.cases.get(context[self.key], self.default)
        case._build(obj, stream, context)
    def _sizeof(self, context):
        case = self.cases.get(context[self.key], self.default)
        return case._sizeof(context)


# def AdapterSwitch(self, subcon, key, cases, init_args, default = None):
#     """Like a FastSwitch, but for adapters instead of constructs.

#     The fact that I need to write this means that something has gone
#     very, very wrong.

#     cases: Dictionary mapping keys to uninitialized adapters.

#     init_args: Dictionary mapping keys to initialization arguments
#     for the adapters minus the construct to wrap.
#     """

#     def __init__(self, subcon, key, cases, default = Switch.NoDefault):
#         Subconstruct.__init__(self, subcon.name, subcon.conflags)
#         self._set_flag(self.FLAG_DYNAMIC)
#         self.subcon = subcon
#         self.cases = cases
#         self.key = key
#         self.default = default
#     def _parse(self, stream, context):
#         case = self.cases.get(context[self.key], self.default)
#         return case._parse(stream, context) 
#     def _build(self, obj, stream, context):
#         case = self.cases.get(context[self.key], self.default)
#         case._build(obj, stream, context)
#     def _sizeof(self, context):
#         case = self.cases.get(context[self.key], self.default)
#         return case._sizeof(context)


class Magic(Adapter):
    """ Mutant combination of Const and Magic.
    """
    __slots__ = ('value', 'error')

    def __init__(self, value, error):
        Adapter.__init__(self, Field(None, len(value)))
        self.value = value
        self.error = error

    def _encode(self, obj, context):
        if obj is None or obj == self.value:
            return self.value
        else:
            raise self.error("expected %r, found %r" % (self.value, obj))

    def _decode(self, obj, context):
        if obj != self.value:
            raise self.error("expected %r, found %r" % (self.value, obj))
        return obj


# The absolutely minimal bloat factor for a zero-parameter packet is
# 24, if I represent opcodes with Python doubles.  If I use ints, it's
# 32.  Using Construct without rewriting it, each packet has to be at
# least 312-320 bytes (an empty Container and an int or a double for
# the opcode) plus whatever the key takes up.  A custom Container
# class using __slots__ might be able to reduce memory (a test class
# with one integer attribute takes 136 bytes), but couldn't be
# dynamic; I don't know if that would cost CPU.  There are other
# possible ways to rewrite Construct, though they would be more
# difficult.

# More practically speaking, my current representations are taking up
# 488-496 bytes.  By moving to command-only using some kind of
# mapping, that will reduce it to 376 bytes if I represent packets
# with only an opcode and 400-408 bytes with only a command.
# Especially since there are lots of multiparameter opcodes, I'm
# skeptical the extra 24-32 bytes are worth the necessary lack of
# clarity, so my first-blush attempt is simply to remove the
# additional command field and replace opcodes with commands.

# Current model: the central Switch statement is based on opcodes.
# Future model: two dictionaries, one that maps opcodes -> command
# names for a Mapping, and one that maps command names -> Structs for
# a Switch.  I initially rejected this setup because it seemed to
# create an unnecessary dictionary, but the need to save memory by not
# embedding the command name in the Structs justifies the second
# dictionary.

# A parsed Container for one of the quadruplets will contain just the
# command name.  To convert it to bytes, there has to be a construct
# with an if statement that sends it to the right opcode.  To convert
# it from bytes, there has to be a map that converts opcodes to
# commands and decides based on the opcode which argument to pass to
# IntField.

class NamedTuple(Adapter):
    __slots__ = ('named_tuples')
    def __init__(self, subcon):
        Adapter.__init__(self, subcon)
        # This dictionary should not be per-instance!!!
        self.named_tuples = {}
    def _decode(self, obj, context):
        try:
            return self.named_tuples[next(obj.itervalues())](**obj)
        except KeyError:
            self.named_tuples[next(obj.itervalues())] = collections.namedtuple('container', obj.keys())
            return self.named_tuples[next(obj.itervalues())](**obj)
    def _encode(self, obj, context):
        return Container().update(vars(obj))


class FixWord(Adapter):
    """ Converts integers to and from a special fixed-point value.

    The clearest explanation of how to calculate a fix_word is in
    vftovp.web:

        The most important data type used here is a fix word, which
        is a 32-bit representation of a binary fraction.  A fix word
        is a signed quantity, with the two's complement of the entire
        word used to represent negation.  Of the 32 bits in a fix word,
        exactly 12 are to the left of the binary point; thus, the
        largest fix word value is 2048 - 2^-20, and the smallest is
        -2048.

    To turn a four-byte integer into a floating point value with 12
    bits to the left of the decimal point, divide by 2^20.  Note that
    sometimes fix_words are defined using integers of other byte
    sizes.  This Adapter wraps integers in Constructs.
    """
    __slots__ = ()
    def _decode(self, obj, context):
        return float(obj)/2**20
    def _encode(self, obj, context):
        return int(obj*2**20)


def PacketSwitch(name, opcodes):
    """My original plan was to use the names of Structs to create a
    'command' field in the parsed dictionary that I could then access
    to figure out where to send the parameters.  When using Switch
    with a dictionary of Structs, what happens is that the Switch's
    name *replaces* the names of each Struct in the dictionary.  This
    means that the names of the inner Structs are meaningless and
    might as well be None.  I can Embed the Switch and that would
    merge the 'fields' dictionary into the top level, but that doesn't
    help with assigning opcodes to commands.  At parsing time, before
    the Switch executes, I can't use lambdas to access the name
    because the Structs in its dictionary aren't instantiated and thus
    don't have names I can access.  Even after they've been
    instantiated, there's nothing in the context dictionary that lists
    the names of the Structs, and there's no (easy) way for me to
    insert code in a Construct object such that it executes during
    parsing.  This really leaves only two workable methods: create an
    extra dictionary that maps opcodes to command names and use Value
    to insert that, or use Value in the Switch dictionary.  I prefer
    the latter because it avoids a superfluous dictionary.
    """

    return Struct(name,
                  Byte('opcode'),
                  Embed(FastSwitch('parameters', 'opcode', opcodes)))

    # return Struct(name,
    #               Byte('opcode'),
    #               Embed(Switch('fields',
    #                            lambda ctx: ctx.opcode, 
    #                            opcodes)))

def Packet(name, opcode, struct):
    return Struct(name,
                  Magic(opcode.to_bytes(1, 'big'), DVILikeError),
                  Embed(struct))


# New design: the inner switch handles strictly opcodes and the
# parsing constructs.  There's an outer switch that contains only
# adapters to convert opcodes to commands and vice versa.


# # Need to break this up somehow, this one adapter is obviously trying
# # to do too much.
# class OpcodeCommandsMap(Adapter):
#     """opcodes_to_commands: a non-one-to-one dictionary mapping opcodes
#     to commands, sometimes multiple opcodes to one command.

#     commands_to_opcodes: a one-to-one dictionary mapping each command
#     to the *first* opcode that corresponds to that command.  The extra
#     opcodes that aren't covered are filled in based on the size of the
#     parameter to be encoded.

#     parametric_commands: a dictionary mapping commands to the name of
#     the single parameter they take.

#     tuplets: a dictionary mapping commands to two-element tuplets of
#     the name of the corresponding parameter and an offset in bits to
#     determine how the size of the parameter is mapped to the opcodes.
#     """

#     __slots__ = ['opcodes_to_commands', 'commands_to_opcodes',
#                  'parametric_commands', 'tuplets']
#     def __init__(self, subcon, opcodes_to_commands,
#                  commands_to_opcodes, parametric_commands, tuplets):
#         Adapter.__init__(self, subcon)
#         self.opcodes_to_commands = opcodes_to_commands
#         self.commands_to_opcodes = commands_to_opcodes
#         self.parametric_commands = parametric_commands
#         self.tuplets = tuplets
#     def _decode(self, obj, context):
#         try:
#             obj['command'] = self.opcodes_to_commands[obj.pop('opcode')]
#             return obj
#         except KeyError:
#             raise MappingError("no opcodes_to_commands mapping for %r [%s]" % 
#                                (obj['command'], self.subcon.name))
#     def _encode(self, obj, context):
#         command = obj.pop('command')
#         try:
#             if command in self.parametric_commands:
                
#             elif command in self.tuplets:
#                 if obj[self.tuplets[command][0]]:
#                     offset =
#                     (obj[self.tuplets[command][0]].bit_length()
#                      + self.tuplets[command][1]) // 8
#                 if not offset or offset < 0:
#                     offset = 0
#                 obj['opcode'] = self.commands_to_opcodes[command] + offset
#             else:
#                 obj['opcode'] = self.commands_to_opcodes[command]
#             return obj
#         except KeyError:
#             raise MappingError("no commands_to_opcodes mapping for %r [%s]" %
#                                (command, self.subcon.name))



# class TupletCommand(Adapter):
#     __slots__ = ('command', 'parameter', 'bit_offset')
#     def __init__(self, subcon, command, opcode, parameter, bit_offset = 0):
#         Adapter.__init__(self, subcon)
#         self.command = command
#         self.opcode = opcode
#         self.parameter = parameter
#         self.bit_offset = bit_offset
#     def _decode(self, obj, context):
#         try:
#             obj['command'] = self.command
#             del obj['opcode']
#             return obj
#         except KeyError:
#             raise DVILikeError
#     def _encode(self, obj, context):
#         try:
#             byte_offset = (obj[self.parameter].bit_length() + 
#                            self.bit_offset) // 8
#             if byte_offset < 0:
#                 byte_offset = 0
#             obj['opcode'] = self.opcode + byte_offset
#             return obj
#         except KeyError:
#             raise DVILikeError


# class ParametricCommand(Adapter):
#     __slots__ = ('command', 'parameter', 'offset')
#     def __init__(self, subcon, command, parameter, offset = 0):
#         Adapter.__init__(self, subcon)
#         self.parameter = parameter
#         self.command = command
#         self.offset = offset
#     def _decode(self, obj, context):
#         try:
#             obj['command'] = self.command
#             obj[self.parameter] = obj.pop('opcode') + self.offset
#             return obj
#         except KeyError:
#             raise DVILikeError
#     def _encode(self):
#         try:
#             obj['opcode'] = obj.pop(self.parameter) - self.offset
#             del obj['command']
#             return obj
#         except KeyError:
#             raise DVILikeError


# I ought to be able to write a declarative structure to transform:

# {command = foo, parameter = 123456789}

# b'\xb0\x07[\xcd\x15'

# And vice versa.
    # """opcodes_to_commands: a many-to-one dictionary mapping opcodes to
    # named tuples of commands and a function that takes a packet and
    # replaces the opcode with a command name and a parameter when
    # required.

    # commands_to_opcodes: a one-to-one dictionary mapping each command
    # to named tuples of the first and last opcodes that correspond to
    # that command and a function that takes a packet and replaces the
    # command name with an appropriate opcocde based on the size of the
    # parameter to be encoded.
    # """


class SwitchAdapter(Subconstruct):
    """Something like an adapter where the encoding and decoding functions
    depend on the object or context.
    """

    __slots__ = ('decoding', 'encoding', 'dkey', 'ekey')
    def __init__(self, subcon, decoding, encoding)
        Subconstruct.__init__(self, subcon)
        self.decoding = decoding
        self.encoding = encoding
        self.dkey = dkey
        self.ekey = ekey
    def _parse(self, stream, context):
        return self.decoding[context[dkey]].decode(self.subcon._parse(stream, context))
    def _build(self, obj, stream, context):
        self.subcon._build(self.encoding[obj[ekey]].encode(obj), stream, context)


# class OpcodeCommandsMap(Subconstruct):
#     """opcodes_to_commands: a many-to-one dictionary mapping opcodes to a
#     function that takes a packet and replaces the opcode with a
#     command name and a parameter when required.

#     commands_to_opcodes: a one-to-one dictionary mapping each command
#     to a function that takes a packet and replaces the
#     command name with an appropriate opcocde based on the size of the
#     parameter to be encoded.
#     """

#     __slots__ = ('opcodes_to_commands', 'commands_to_opcodes')
#     def __init__(self, subcon, opcodes_to_commands, commands_to_opcodes)
#         Subconstruct.__init__(self, subcon)
#         self.opcodes_to_commands = opcodes_to_commands
#         self.commands_to_opcodes = commands_to_opcodes
#     def _parse(self, stream, context):
#         return self.opcodes_to_commands[context['opcode']].decode(self.subcon._parse(stream, context))
#     def _build(self, obj, stream, context):
#         self.subcon._build(self.commands_to_opcodes[obj['command']].encode(obj), stream, context)


# Meta-opcode functions

def OneParameterCommand(name, parameter):
    return Struct(name, parameter)

# Okay, I now how to do this now, but even knowing how to do it the
# result is ugly as hell.

# The central FastSwitch code stays the same.  Everything gets wrapped
# in an adapter that takes two dictionaries of functions that are
# essentially equivalent to the decode and encode functions below, one
# dictionary keyed off opcodes and the other keyed off commands.  In
# practice, at this point, with three dictionaries all of which need
# to be synchronized, I should be writing a class that maintains two
# dictionaries internally, one of tuples of pairs of functions that's
# keyed off of opcodes and another of functions.  _opcode_range should
# be a method of this function, as well as other methods for setting
# opcodes.  Might be worth implementing a custom mapping interface to
# allow ChainMap to work.  Fundamentally, though, this is *really*
# complicated and also has the problem that the command always ends up
# at the end of the packet rather than the beginning.  My original
# solution or a close analog (using some kind of specialized Switch
# that dispatches incoming packets to constructs based on parameter
# sizes) is probably better despite its memory intensiveness.


# Rethinking how I'm thinking about these opcode-command setups.

# Three kinds of ranges:

# Quadruplets that all have a single parameter of varying
# sizes.

# Effective quintuplets that have a range of opcodes representing a
# single parameter up to a specific size, then a quadruplet of opcodes
# handling the same parameter when it's larger than that range.

# Simple quintuplets with one parameter-less opcode and a set of four
# opcodes with a single parameter.

# These can all be encoded by one function that takes the following
# arguments: the length of the starting range (the set of opcodes that
# take no parameter), a boolean representing whether the opcode is the
# parameter (false for the simple quintuplets, true for the effective
# quintuplets, irrelevant for the quadruplets), the starting opcode,
# the command name, the parameter name, and then the necessary
# functions and dictionaries for building the mappings and the
# constructs.

# Non-parametric opcodes
def decode0(command, obj):
    obj['command'] = command
    del obj['opcode']
    return obj

# Parametric opcodes in the effective quadruplets
def decode1(command, parameter, opcode, obj):
    obj['command'] = command
    obj[parameter] = obj.pop('opcode') + opcode
    return obj

# One-to-one command-opcodes
def encode0(opcode, obj):
    obj['opcode'] = opcode
    del obj['command']
    return obj

# All the one-to-many command-opcodes
def encode1(opcode, parameter, range_length, bit_offset, obj):
    del obj['command']
    bits = obj[parameter].bit_length()
    # range_length in bits
    if bits < range_length:
        obj['opcode'] = obj.pop(parameter) - opcode
    # range_length should be zero for the quintuplets
    else:
        byte_offset = (bits + bit_offset) // 8
        if byte_offset < 0:
            byte_offset = 0
        obj['opcode'] = opcode + byte_offset
    return obj

# decoding = collections.namedtuple('decoding', 'command decode')
# encoding = collections.namedtuple('encoding', 'first_opcode last_opcode encode')

def _opcode_range(opcode_structs, opcodes_to_commands,
                  commands_to_opcodes, command, opcode, range_length,
                  parameter_structs, bit_offset, parameter =
                  'parameter', struct = OneParameterCommand):
    if range_length > 0:
        for i in range(opcode, opcode + 2**range_length):
            opcode_structs[i] = Pass
            opcodes_to_commands[i] = functools.partial(decode1, command, parameter, opcode)
            opcode =+ 2**range_length
    else:
        opcode_structs[opcode] = Pass
        opcodes_to_commands[opcode] = functools.partial(decode0, command)
    for i in parameter_structs:
        opcode_structs[i + opcode] = struct(command, parameter_structs[i](parameter))
        opcodes_to_commands[i + opcode] = functools.partial(decode0, command)
    commands_to_opcodes[command] = functools.partial(opcode, parameter, range_length, bit_offset)


    # if range_length > 0:
    #     for i in range(opcode, opcode + 2**range_length):
    #         opcode_structs[i] = Pass
    #         opcodes_to_commands[i] = decoding(command, functools.partial(decode1, command, parameter, opcode))
    # else:
    #     opcode_structs[opcode] = Pass
    #     opcodes_to_commands[opcode] = decoding(command, functools.partial(decode0, command))
    # for i in parameter_structs:
    #     opcode_structs[i + opcode] = struct(command, parameter_structs[i](parameter))
    #     opcodes_to_commands[i + opcode] = decoding(command, functools.partial(decode0, command))
    # commands_to_opcodes[command] = encoding(command, opcode, opcode + 2**range_legnth + 4, 


# def _opcode_tuplet(opcode_structs, opcodes_to_commands,
#                    commands_to_opcodes, command, start, offset,
#                    parameter_structs, parameter =
#                    'parameter', struct = OneParameterCommand):
#     commands_to_opcodes[command] = start
#     for i in parameter_structs:
#         opcode_structs[i + start] = struct(command, parameter_structs[i](parameter))
#         opcodes_to_commands[i + start] = decoding(command, 0

# def _opcode_range(opcode_structs, opcodes_to_commands, command, start,
#                   stop, parametric_commands, struct, parameter =
#                   'parameter'):
#     parametric_commands[command] = parameter
#     for i in range(start, stop):
#         opcode_structs[i] = struct(i)
#         opcodes_to_commands[i] = command


class DictLikeChainMap(collections.ChainMap):
    """Adds the keys(), values(), and items() methods to a ChainMap."""

    # These three classes implements something like PEP 3106
    # (legacy.python.org/dev/peps/pep-3106/) for ChainMaps. For these
    # purposes, I'm going to treat a ChainMap exactly like a
    # dictionary with the same keys and the items and values
    # corresponding to those keys.  If a value or item can't be
    # accessed by any key, this won't return it.  The methods needed
    # to implement view objects for a ChainMap are exactly those
    # contained in the collections abstract base classes.

    items = collections.abc.ItemsView
    keys = collections.abc.KeysView
    values = collections.abc.ValuesView

    # def items(self):
    #     return collections.abc.ItemsView(self)

    # def keys(self):
    #     return collections.abc.KeysView(self)

    # def values(self):
    #     return collections.abc.ValuesView(self)


FILE_TYPES = dict(DVI = 2, DVIV = 3, XDV = 5, PK = 131, VF = 202)

class DVILikeError(ConstructError):
    pass
class PreambleError(DVILikeError):
    pass
class PostambleError(DVILikeError):
    pass


class DVILikeProcessor(abc.ABC):
    """ Abstract class for parsing opcode-based TeX files like DVI files.

    The canonical references for the VF (virtual font) and DVI
    (device-independent) formats are vftovp.web and dvitype.web,
    respectively.  Both formats share the same basic structure:
    they're set up as a series of commands, each command starting with
    one byte that represents an opcode and the rest of the bytes
    parameters for that command.  TFM files use a different format.

    This abstract class contains methods that the rest of the classes
    that parse and build VF and DVI files inherit.  Methods of this
    class and its subclasses should only raise errors that prevent
    parsing or building, like unexpected termination of the input,
    commands that start with undefined opcodes, or containers with
    missing parameters.  For some applications, like dvitype or
    dviasm, the ability to handle malformed input is an advantage: for
    instance, they might be used to debug programs that make DVI files
    or to fix broken DVI files.  Most errors should be raised by
    methods of the classes that produce output, subclassses of
    OpcodeCommandsMachine.

    Doesn't catch errors like fnt or fnt_num commands referring to
    font numbers that haven't been defined, negative design sizes, or
    similar problems that require detailed parsing of the file.
    """

    PreambleStart = Struct(None, Magic(b'\367', PreambleError),
                           Enum(Byte('file_type'), **FILE_TYPES))

    @abc.abstractmethod
    def __init__(self, data, file_type):
        raise NotImplementedError
        #        self.load(data)
        #        self._opcodes = {}
        #        self.File = GreedyRange(PacketSwitch(None, self._opcodes))

    @classmethod
    def Process(cls, data):
        def descendants(ancestor):
            yield from set(ancestor.__subclasses__()) | {c for s in ancestor.__subclasses__() for c in descendants(s)}

        if all([hasattr(data, attr) for attr in ['read', 'seek', 'tell']]):
            file_type = cls.PreambleStart.parse_stream(data).file_type
        else:
            file_type = cls.PreambleStart.parse(data).file_type
        for subclass in descendants(cls):
            if file_type in subclass.TYPES:
                return subclass(data, file_type)
        raise NameError('Processor not found for a ' + file_type + ' file.')

    @abc.abstractmethod
    def __iter__(self):
        self._buffer.seek(0, 0)
        self.command = self.Preamble.parse_stream(self._buffer).command
        return self

    def load(self, data):
        if all([hasattr(data, attr) for attr in ['read', 'seek', 'tell']]):
            self._buffer = data
            self._buffer.seek(0, 0)
        else:
            self._buffer = io.BytesIO(data)
        #        self._end = self._buffer.seek(0, 2)

    def read_file(self, infile):
        return self.File.parse_stream(infile)

    def read_bytes(self, inmemory):
        return self.File.parse(inmemory)

    def write_file(self, container, outfile):
        return self.File.build_stream(container, outfile)

    def write_bytes(self, container):
        return self.File.build(container)


# Breaking down what opcodes are allowed where.

# VF files:

# pre at the beginning, then fnt_defs, then only character packets,
# then postamble.  DVI code allowed in the character packets are
# everything but bop, eop, fnt_defs, pre, post, and post_post.

# DVI files:

# pre at the beginning, then everything except post and post_post,
# then post, then fnt_defs and nop, then post_post.  Inside pages,
# everything but pre, post, post_post, and bop.

# pTeX files:

# Add dir inside pages.

# XDV files:

# Add dir and the other XDV opcodes inside pages; native_font_def
# between pages, inside pages, and in the postamble.

class VFDVIProcessor(DVILikeProcessor):
    TYPES = []

    def __init__(self):
        mixed_quadruplet = (-1, {0: Byte, 1: UBInt16, 2: UBInt24, 3:
                            SBInt32})
        signed_quadruplet = (0, {0: SBInt8, 1: SBInt16, 2: SBInt24, 3:
                            SBInt32})
        signed_quintuplet = (8, {0: lambda name: Pass, 1: SBInt8, 2:
                             SBInt16, 3: SBInt24, 4: SBInt32})

        def FntDef(command, Parameter):
            return Struct('fnt_def',
                          Command('fnt_def'),
                          Parameter, # font_num
                          SBInt32('checksum'),
                          FixWord(SBInt32('scale_factor')),
                          FixWord(SBInt32('design_size')),
                          Byte('a'),
                          Byte('l'),
                          String('tex_name', lambda ctx: ctx['a']+ctx['l'], 'ascii'))
        self.DVI_OPCODES = {}
        self.FONT_DEF_OPCODES = {}
        _opcode_tuplet(self.FONT_DEF_OPCODES, 243, FntDef)

        self.DVI_OPCODES = {}
        self.DVI_OPCODES.update({132 : Struct('set_rule',
                                               Command('set_rule'),
                                               SBInt32('height'),
                                               SBInt32('width')),
                                  137 : Struct('put_rule',
                                               Command('put_rule'),
                                               SBInt32('height'),
                                               SBInt32('width')),
                                  138 : Pass,
                                  141 : Struct('push', Command('push')),
                                  142 : Struct('pop', Command('pop'))
                              })

        FntNum = Struct('fnt_num',
                        Command('fnt_num'),
                        Value('font_num', lambda ctx: ctx['opcode'] - 171))
        _opcode_range(self.DVI_OPCODES, 0, 128, Struct('set_char',
                                                        Command('set_char')))
        _opcode_range(self.DVI_OPCODES, 171, 235, FntNum)

        def Xxx(i, signed):
            return Struct('xxx',
                          Command('xxx'),
                          PascalString('x',
                                       IntField('k', i, 'big', signed),
                                       'ascii'))
 
        _opcode_mixed_quadruplet(self.DVI_OPCODES, 128,
                                 _one_parameter_opcode('set', 'char_code'))
        _opcode_mixed_quadruplet(self.DVI_OPCODES, 133,
                                 _one_parameter_opcode('put', 'char_code'))
        _opcode_signed_quadruplet(self.DVI_OPCODES, 143,
                                  _one_parameter_opcode('right', 'b'))
        _opcode_signed_quintuplet(self.DVI_OPCODES, 147, 'w', 'b')
        _opcode_signed_quintuplet(self.DVI_OPCODES, 152, 'x', 'b')
        _opcode_signed_quadruplet(self.DVI_OPCODES, 157,
                                  _one_parameter_opcode('down', 'a'))
        _opcode_signed_quintuplet(self.DVI_OPCODES, 161, 'y', 'a')
        _opcode_signed_quintuplet(self.DVI_OPCODES, 166, 'z', 'a')
        _opcode_mixed_quadruplet(self.DVI_OPCODES, 235,
                                 _one_parameter_opcode('fnt', 'font_num'))
        _opcode_mixed_quadruplet(self.DVI_OPCODES, 239, Xxx)
        

class VFProcessor(VFDVIProcessor):
    TYPES = ['VF']

    def __init__(self, data = b'', file_type = 'VF'):
        self.load(data)
        super().__init__()

        self.CHAR_OPCODES = {}
        DVICode = OptionalGreedyRange(PacketSwitch('dvi_code',
                                                   self.DVI_OPCODES))
        ShortChar = Struct('short_char',
                           Command('short_char'),
                           Byte('char_code'),
                           FixWord(UBInt24('tfm_width')),
                           Tunnel(Field('dvi_code', lambda ctx: ctx['opcode']),
                                  DVICode))
        _opcode_range(self.CHAR_OPCODES, 0, 242, ShortChar)
        self.CHAR_OPCODES[242] = Struct('long_char',
                                        Command('long_char'),
                                        SBInt32('dvi_length'),
                                        SBInt32('char_code'),
                                        FixWord(SBInt32('tfm_width')),
                                        Tunnel(
                                            Field('dvi_code',
                                                  lambda ctx: ctx['dvi_length']),
                                            DVICode))
        VFPre = Struct('pre',
                       Command('pre'),
                       Magic(b'\312', PreambleError), 
                       PascalString('comment', encoding = 'ascii'),
                       SBInt32('checksum'),
                       FixWord(SBInt32('design_size')))
        self.Preamble = Packet('pre', 247, VFPre)
        VFPost = Struct('post',
                        Command('post'),
                        Range(0, 3, Magic(b'\370', PostambleError)),
                        Terminator)
        self.File = Struct(None,
                           self.Preamble,
                           OptionalGreedyRange(
                               PacketSwitch('fonts', self.FONT_DEF_OPCODES)),
                           OptionalGreedyRange(
                               PacketSwitch('chars', self.CHAR_OPCODES)),
                           Packet('post', 248, VFPost))
        # commands = {('pre',) : 'pre', ('fnt_def',) : 'fnt_def', ('short_char', 'long_char') : 'char', ('post',) : 'post'}
        # {x for command in commands for x in command}
        # {x for x in itertools.chain(*commands)}
        # transitions = {'pre' : {'start' : 'fonts'}, 
        #                'fnt_def' : {'fonts': 'fonts'},
        #                'char' : {'fonts' : 'chars', 'chars' : 'chars'},
        #                'post' : {'chars' : 'end'}}
        self.Font = PacketSwitch(None, DictLikeChainMap(self.FONT_DEF_OPCODES, self.CHAR_OPCODES))
        self.Char = PacketSwitch(None, DictLikeChainMap(self.CHAR_OPCODES, {248 : VFPost}))
        actions = {'start' : self.Preamble.parse_stream, 'fonts' : Font.parse_stream, 'chars' : Char.parse_stream}
        transitions = {('pre',): {'start' : 'fonts'}, 
                       ('fnt_def',) : {'fonts': 'fonts'},
                       ('short_char', 'long_char') : {'fonts' : 'chars', 
                                                     'chars' : 'chars'},
                       ('post',) : {'chars' : 'end'}}
        t = {command : states for commands, states in transitions.items() for command in commands}
        a = {command : actions for command in t}
        self.iterator = dvilike_machine(t, a, self._buffer)

    def __iter__(self):
        yield self.Preamble.parse_stream(self._buffer)
        while True:
            packet = self.Font.parse_stream(self._buffer)
            yield packet
            if packet['command'] != 'fnt_def':
                break
        while True:
            packet = self.Char.parse_stream(self._buffer)
            yield packet
            if packet['command'] == 'post':
                self._buffer.seek(0,0)
                return


# class VFDVIProcessor(DVILikeProcessor):
#     def __init__(self, data = b''):#         # DVILikeProcessor.__init__(self, data)
#         self.load(data)
#         # Opcodes 250-255 aren't allowed either but aren't defined in DVI
#         self._opcodes = _page_opcodes
#         self.File = GreedyRange(PacketSwitch(None, self._opcodes))


class DVIProcessor(VFDVIProcessor):
    TYPES = ['DVI', 'DVIV', 'XDV']

    def __init__(self, data = b'', file_type = 'DVI'):
        # DVILikeProcessor.__init__(self, data)
        self.load(data)
        # self._temp()
        super().__init__()

        DVIPre = Struct('pre',
                        Command('pre'),
                        Magic(FILE_TYPES[file_type].to_bytes(1, 'big'), 
                              PreambleError),
                        SBInt32('numerator'),
                        SBInt32('denominator'),
                        SBInt32('magnification'),
                        PascalString('comment', encoding = 'ascii'))
        self.BETWEEN_PAGES_OPCODES = DictLikeChainMap(self.FONT_DEF_OPCODES, {138: Pass})
        self.PAGE_OPCODES = DictLikeChainMap(self.FONT_DEF_OPCODES, self.DVI_OPCODES)

        if file_type == 'DVIV' or file_type == 'XDV':
            self.PAGE_OPCODES[255] = Struct('dir', Command('dir'), Flag('dir'))

        if file_type == 'XDV':
            class TransformMatrix(Adapter):
                """Converts an array of integers from and to a matrix of floats.
                
                Xetex's pic_file command includes a transformation
                matrix for the image.  The code to read it is in
                xdvipdfmx's dvi.c in do_pic_file() on lines 1978-1843,
                with the comment, "transform is a 3x2 affine transform
                matrix expressed in fixed-point values."  This Adapter
                wraps an Array of integers.
                """
                def _decode(self, obj, context):
                    return [[float(obj[0])/2**16, float(obj[1])/2**16],
                            [float(obj[2])/2**16, float(obj[3])/2**16],
                            [float(obj[4])/2**16, float(obj[5])/2**16]]
                def _encode(self, obj, context):
                    return [int(obj[0][0]*2**16), int(obj[0][1]*2**16),
                            int(obj[1][0]*2**16), int(obj[1][1]*2**16),
                            int(obj[2][0]*2**16), int(obj[2][1]*2**16)]
            
            DefineNativeFont = Struct('define_native_font',
                                      Command('define_native_font'),
                                      UBInt32('font_num'),
                                      UBInt32('point_size'),
                                      Embed(BitStruct(None,
                                                      Padding(1),
                                                      Flag('embolden_flag'),
                                                      Flag('slant_flag'),
                                                      Flag('extend_flag'),
                                                      Flag('variations'),
                                                      Flag('features'),
                                                      Flag('colored'),
                                                      Flag('vertical'),
                                                      Padding(8))),
                                      Byte('lenps'),
                                      Byte('lenfam'),
                                      Byte('lensty'),
                                      String('ps_name',
                                             lambda ctx: ctx['lenps'],
                                             'ascii'),
                                      String('family',
                                             lambda ctx: ctx['lenfam'],
                                             'ascii'),
                                      String('style',
                                             lambda ctx: ctx['lensty'],
                                             'ascii'),
                                      If(lambda ctx: ctx['colored'],
                                         UBInt32('rgba')),
                                      If(lambda ctx: ctx['extend_flag'],
                                         SBInt32('extend')),
                                      If(lambda ctx: ctx['slant_flag'],
                                         SBInt32('slant')),
                                      If(lambda ctx: ctx['embolden_flag'],
                                         SBInt32('embolden')),
                                      If(lambda ctx: ctx['variations'],
                                         Embed(Struct(
                                             None,
                                             UBInt16('nv'),
                                             Array(lambda ctx: ctx['nv'],
                                                   SBInt32('axes')),
                                             Array(lambda ctx: ctx['nv'],
                                                   SBInt32('values'))))))

            def SetGlyph(name, construct):
                return Struct(None,
                              Command('set_glyph_' + name),
                              SBInt32('width'),
                              UBInt16('glyph_count'),
                              Array(lambda ctx: ctx['glyph_count'], construct),
                              Array(lambda ctx: ctx['glyph_count'],
                                    UBInt16('glyph_id')))

            self.PAGE_OPCODES[251] = Struct('pic_file',
                                            Command('pic_file'),
                                            # TODO: This needs some commenting
                                            # to explain what this byte is,
                                            # see 1994 of dvi.c
                                            Byte('pdf_box'),
                                            TransformMatrix(Array(6,
                                                                  SBInt32('transform_matrix'))),
                                            UBInt16('page_number'),
                                            PascalString('path', UBInt16('length'), 'ascii'))

            self.BETWEEN_PAGES_OPCODES[252] = DefineNativeFont
            self.PAGE_OPCODES[252] = DefineNativeFont
            self.PAGE_OPCODES[253] = SetGlyph('array', Struct('loc',
                                                              SBInt32('x'),
                                                              SBInt32('y')))
            self.PAGE_OPCODES[254] = SetGlyph('string', SBInt32('xloc'))

        DVIPost = Struct('post',
                         Command('post'),
                         SBInt32('p'),
                         SBInt32('numerator'),
                         SBInt32('denominator'),
                         SBInt32('magnification'),
                         SBInt32('page_height_plus_depth'),
                         SBInt32('page_width'),
                         UBInt16('max_stack_depth'),
                         UBInt16('total_pages'))

        PostPost = Struct('post_post',
                          Command('post_post'),
                          SBInt32('q'),
                          Magic(FILE_TYPES[file_type].to_bytes(1, 'big'),
                                PostambleError),
                          Range(4, 7, Magic(b'\337', PostambleError)),
                          Terminator)

        Bop = Struct('bop',
                     Command('bop'),
                     Array(10, SBInt32('c')),
                     SBInt32('p'))

        self.Preamble = Packet('pre', 247, DVIPre)

        def BetweenPages(name):
            return PacketSwitch(name, self.BETWEEN_PAGES_OPCODES)

        # self.File = Struct(None,
        #                    self.Preamble,
        #                    OptionalGreedyRange(BetweenPages('before_pages')),
        #                    # The names in a Sequence are meaningless,
        #                    # but for some reason they can't be None,
        #                    # so I used one-element strings.
        #                    OptionalGreedyRange(Sequence('page',
        #                                                 Packet('a', 139, Bop),
        #                                                 OptionalGreedyRange(PacketSwitch('b', self.PAGE_OPCODES)),
        #                                                 Packet('c', 140, Struct('eop', Command('eop'))),
        #                                                 OptionalGreedyRange(BetweenPages('d')))),
        #                    Packet('post', 248, DVIPost),
        #                    OptionalGreedyRange(BetweenPages('fonts')),
        #                    Packet('post_post', 249, PostPost))


        self.File = Struct(None,
                           NamedTuple(self.Preamble),
                           OptionalGreedyRange(NamedTuple(BetweenPages('before_pages'))),
                           # The names in a Sequence are meaningless,
                           # but for some reason they can't be None,
                           # so I used one-element strings.
                           OptionalGreedyRange(Sequence('page',
                                                        NamedTuple(Packet('a', 139, Bop)),
                                                        OptionalGreedyRange(NamedTuple(PacketSwitch('b', self.PAGE_OPCODES))),
                                                        NamedTuple(Packet('c', 140, Struct('eop', Command('eop')))),
                                                        OptionalGreedyRange(NamedTuple(BetweenPages('d'))))),
                           NamedTuple(Packet('post', 248, DVIPost)),
                           OptionalGreedyRange(NamedTuple(BetweenPages('fonts'))),
                           NamedTuple(Packet('post_post', 249, PostPost)))


        # commands = {('pre',) : 'pre',
        #             ('fnt_def',) : 'fnt_def',
        #             ('set_char', 'set', 'set_rule', 'put', 'put_rule', 'push', 'right', 'w', 'x', 'down', 'y', 'z', 'fnt_num', 'fnt', 'xxx') : 'page_op',
        #             ('bop',) : 'bop',
        #             ('eop',) : 'eop',
        #             ('post',) : 'post',
        #             ('post_post',) : 'post_post'}
        # transitions = {'pre' : {'start' : 'between_pages'}, 
        #                'bop' : {'between_pages' : 'in_page'},
        #                'page_op' : {'in_page' : 'in_page'},
        #                'eop' : {'in_page', 'between_pages'},
        #                'fnt_def' : {'in_page' : 'in_page', 'between_pages' : 'between_pages', 'fonts' : 'fonts'}
        #                'post' : {'between_pages' : 'fonts'},
        #                'post_post' : {'fonts' : 'end'}}

        self.BetweenPagesTwo = PacketSwitch(None, self.BETWEEN_PAGES_OPCODES.new_child({139 : Bop, 248 : DVIPost}))
        self.InPage = PacketSwitch(None, self.PAGE_OPCODES.new_child({140 : Struct('eop', Command('eop'))}))
        self.Postamble = PacketSwitch(None, self.BETWEEN_PAGES_OPCODES.new_child({249: PostPost}))
        actions = {'start' : self.Preamble.parse_stream, 'between_pages' : self.BetweenPagesTwo.parse_stream, 'in_page' : self.InPage.parse_stream, 'postamble' : self.Postamble.parse_stream}
        transitions = {('pre',) : {'start' : 'between_pages'}, 
                       ('bop',) : {'between_pages' : 'in_page'},
                       ('set_char', 'set', 'set_rule', 'put', 'put_rule', 'push', 'right', 'w', 'x', 'down', 'y', 'z', 'fnt_num', 'fnt', 'xxx') : {'in_page' : 'in_page'},
                       ('eop',) : {'in_page', 'between_pages'},
                       ('fnt_def',) : {'in_page' : 'in_page', 'between_pages' : 'between_pages', 'postamble' : 'postamble'},
                       ('post',) : {'between_pages' : 'postamble'},
                       ('post_post',) : {'postamble' : 'end'}}
        t = {command : states for commands, states in transitions.items() for command in commands}
        a = {command : actions for command in t}

    def __iter__(self):
        yield self.Preamble.parse_stream(self._buffer)
        while True:
            while True:
                packet = self.BetweenPagesTwo.parse_stream(self._buffer)
                yield packet
                if packet is not None and (packet['command'] == 'bop' or packet[command] == 'post'):
                    break
            while packet['command'] != 'post':
                packet = self.InPage.parse_stream(self._buffer)
                yield packet
                if packet['command'] == 'eop':
                    break
            if packet['command'] == 'post':
                break
        while True:
            print(packet['command'])
            packet = self.Postamble.parse_stream(self._buffer)                
            yield packet
            if packet is not None and packet['command'] == 'post_post':
                self._buffer.seek(0,0)
                return

    def postamble(self):
        print(self._buffer.seek(-1, 2))
        # Don't care what the id byte is at this point, it gets checked later.
        while self._buffer.read(1) == b'\337':
            print(self._buffer.seek(-2, 1))
        print(self._buffer.seek(-6, 1))
        post_post = Packet(None, 249, PostPost(self.id_byte)).parse_stream(self._buffer)
        self._buffer.seek(post_post.q, 0)
        post = Packet(None, 248, DVIPost()).parse_stream(self._buffer)
        return [post,
                GreedyRange(PacketSwitch(None, self._post_opcodes)).parse_stream(self._buffer)]

    def pages(self):
        previous_page = self.postamble()[0].p
        while previous_page > 0:
            print(self._buffer.seek(previous_page, 0))
            previous_page = Packet(None, 139, Bop()).parse_stream(self._buffer).p
            yield RepeatUntil(lambda obj, ctx: obj['command'] == 'eop', PacketSwitch(None, self._page_opcodes)).parse_stream(self._buffer)


class PKProcessor(DVILikeProcessor):
    TYPES = ['PK']
    
    def __init__(self, data = b'', file_type = 'PK'):
        raise NotImplementedError


# class DVIVProcessor(DVIProcessor):
#     def __init__(self, data = b''):
#         DVIProcessor.__init__(self, data)
#         self._id_byte = b'\3'
#         self._page_opcodes[255] = Struct(None, Command('dir'), Flag('dir'))
#         self.File = DVIFormat(self._id_byte, self._post_opcodes, self._page_opcodes)
#         self._opcodes0[248] = DVIPost()
#         self._opcodes1[255] = Struct(None, Command('dir'), Flag('dir'))
#         self._opcodes2[249] = PostPost(self._id_byte)


# class XDVProcessor(DVIVProcessor):
#     def __init__(self, data = b''):
#         DVIVProcessor.__init__(self, data)
#         self._id_byte = b'\5'
#         self._page_opcodes.update(_xdv_opcodes)
#         self._post_opcodes[252] = DefineNativeFont()
#         self.File = DVIFormat(self._id_byte, self._post_opcodes, self._page_opcodes)
#         self._opcodes0[248] = DVIPost()
#         self._opcodes0[252] = DefineNativeFont()
#         self._opcodes1.update(_xdv_opcodes)
#         self._opcodes2[249] = PostPost(self._id_byte)
#         self._opcodes2[252] = DefineNativeFont()

# http://stackoverflow.com/questions/2101961/python-state-machine-design#answer-2102001

# http://code.activestate.com/recipes/146262-finite-state-machine-fsm/

# https://wiki.python.org/moin/State%20Machine%20via%20Decorators

# https://github.com/oxplot/fysom

# http://www.ibm.com/developerworks/linux/library/l-python-state/index.html

# http://www.ibm.com/developerworks/linux/library/l-pygen/index.html

# http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-01sc-introduction-to-electrical-engineering-and-computer-science-i-spring-2011/unit-1-software-engineering/state-machines/MIT6_01SCS11_chap04.pdf

# http://www2.research.att.com/~fsmtools/fsm/man4/fsmpy.html

# Has discussion of iterators in the context of FSMs.


def coroutine(func):
    def primed(*args, **kwds):
        cr = func(*args, **kwds)
        cr.send(None)
        return cr
    return primed


class UndefinedActionError(Exception):
    pass
class IllegalTransitionError(Exception):
    pass

# There are two different use cases here with contradictory
# restraints: for the state machines in the parser, the actions are
# tied to the states, but for the transformer, they're tied to the
# commands.  There's shared code, though, so the special-casing should
# be done outside the state machine coroutine.
@coroutine
def dvilike_machine(transitions, actions, start = 'start', **state_vars):
    """No.

    transitions: Dictionary mapping commands (strings) to dictionaries
    mapping states (strings) to a state (a string).

    actions: Dictionary mapping commands (strings) to dictionaries
    mapping states to an action (a function).

    start: The start state (a string).

    """
    # at = {}
    # for command in a:
    #     for state in a:
    #         at[command][state] = {}
    #         at[command][state][action] = a if a[command][state]
    #         at[command][state][transition] = t if t[command][state]

    # at = {
    #     command: {
    #         state: [transitions[command][state], actions[state]]
    #         for state in {x for x in itertools.chain(*transitions)}
    #     }
    #     for command in {x for x in itertools.chain(*commands)}
    # }

    state = start

    while True:
        command = (yield)
        try:
            state = transitions[command][state]
        except KeyError as e:
            raise IllegalTransitionError(e)
        try:
            state_vars = actions[command][state](**state_vars)
        except KeyError as e:
            raise UndefinedActionError(e)


class DVILikeMachine:
    """

    events: Dictionary mapping tuples of commands (strings) to events
    (strings) for the state machine.  All commands the state machine
    accepts must be keys in this dictionary.  Passing any command not
    in this dictionary to the state machine will cause it to raise an
    exception.
    
    transitions: Dictionary mapping events (strings) to dictionaries
    mapping states (strings) to states (strings).

    actions: Dictionary mapping commands (strings) to
    actions (functions).
    The default method for a command is the method
    with the same name as the command---this dictionary allows you to
    override that.  If a method doesn't exist, the default method is
    called instead.  The default for the default method is to do
    nothing, but this can also be overriden.
    """

    def __init__(self, events, transitions, actions):
        self._events = events
        self._transitions = transitions
        self._actions = actions

    def __call__(self, container):
        try:
            func = getattr(self, 'do_' + cmd)
        except AttributeError:
            return self.default(container)
        self._commands[container.command](container)
        return func(arg)

    def default(self, container):
        raise NotImplementedError


class OpcodeCommandsMachine:
    """ Use by calling the constructor, then feeding execute() commands as Construct Containers one at a time."""
    def __init__(self):
        self._commands = {'fnt_def' : self.fnt_def,
                          'pre' : self.pre,
                          'post' : self.post,
                          # DVI commands
                          'set_char' : self.set_char,
                          'set' : self.set,
                          'set_rule' : self.set_rule,
                          'put' : self.put,
                          'put_rule' : self.put_rule,
                          'bop' : self.bop,
                          'eop' : self.eop,
                          'push' : self.push,
                          'pop' : self.pop,
                          'right' : self.right,
                          'w' : self.w,
                          'x' : self.x,
                          'down' : self.down,
                          'y' : self.y,
                          'z' : self.z,
                          'fnt_num' : self.fnt,
                          'fnt' : self.fnt,
                          'xxx' : self.xxx,
                          'post_post' : self.post_post,
                          # VF commands
                          'short_char' : self.char,
                          'long_char' : self.char,
                          # XDV commands
                          'pic_file' : self.pic_file,
                          'define_native_font' : self.define_native_font,
                          'set_glyph_array' : self.set_glyph,
                          'set_glyph_string': self.set_glyph,
                          # pTeX commands
                          'dir' : self.dir
                          }

    def __call__(self, container):
        self._commands[container.command](container)

    # Shared commands
    def fnt_def(self, container):
        raise NotImplementedError
    def pre(self, container):
        raise NotImplementedError
    def post(self, container):
        raise NotImplementedError

    # DVI commands
    def set_char(self, container):
        raise NotImplementedError
    def set(self, container):
        raise NotImplementedError
    def set_rule(self, container):
        raise NotImplementedError
    def put(self, container):
        raise NotImplementedError
    def put_rule(self, container):
        raise NotImplementedError
    def bop(self, container):
        raise NotImplementedError
    def eop(self, container):
        raise NotImplementedError
    def push(self, container):
        raise NotImplementedError
    def pop(self, container):
        raise NotImplementedError
    def right(self, container):
        raise NotImplementedError
    def w(self, container):
        raise NotImplementedError
    def x(self, container):
        raise NotImplementedError
    def down(self, container):
        raise NotImplementedError
    def y(self, container):
        raise NotImplementedError
    def z(self, container):
        raise NotImplementedError
    def fnt(self, container):
        raise NotImplementedError
    def xxx(self, container):
        raise NotImplementedError
    def post_post(self, container):
        raise NotImplementedError

    # VF commands
    def char(self, container):
        raise NotImplementedError

    # XDV commands
    def pic_file(self, container):
        raise NotImplementedError
    def define_native_font(self, container):
        raise NotImplementedError
    def set_glyph(self, container):
        raise NotImplementedError

    # pTeX commands
    def dir(self, container):
        raise NotImplementedError        



if __name__ == "__main__":

    # file = 'DroidSerif-Regular-ot1.vf'
    # file = 'extending_hardys_proof.dvi'
    # file = 'testsuite/F-alias-feature-option.xdv'
    # file = '02_xits_fonts.xdv'
    # file = 'droid-test.dvi'
    file = 'pcml-16.dvi'

    with open(file, 'rb') as f:
        test = DVILikeProcessor.Process(f)
        # t = test.read_file(f)
        # for x in test:
        # tracker = pympler.classtracker.ClassTracker()
        # tracker.track_class(Container)
        # tracker.track_class(ListContainer)
        #     print(x)
        print(test.read_file(f))
        # for x in t.itervalues():
        #     print(x)
        #     print(pympler.asizeof.asizeof(x, stats = 1), pympler.asizeof.leng(x))
        # print(asizeof(t, stats = 1), leng(t))
        # print(pympler.asizeof.asizeof(all = True))
        # print(test.postamble())
        # i = 0
        # for x in test.pages():
        #     i = i + 1
        #     print('Page ' + str(i))
        #     for y in x:
        #         print(y)

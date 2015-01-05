#!/usr/bin/python3

from construct import (Adapter, Array, BitStruct, Construct, Debugger, Embed,
                       Field, FieldError, Flag, GreedyRange, If, Magic,
                       OptionalGreedyRange, Padding, PascalString, Pass, Probe, Range, RepeatUntil,
                       Sequence, StaticField, String, Struct, Switch, Terminator, UBInt8,
                       UBInt16, SBInt32, UBInt32, Value)
import sys
import io
import pdb
import collections


# The high-high level architecture of this program works like:

# DVILikeTranslator parses a file to create a representation in Python.

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

    __slots__ = ['byteorder', 'signed']

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


# The following two functions are copied verbatim from
# construct/core.py.  They're called in FormatField and serve the same
# function in IntField but aren't part of the external interface to
# the construct module, so I had to duplicate the code here.
def _read_stream(stream, length):
    if length < 0:
        raise ValueError("length must be >= 0", length)
    data = stream.read(length)
    if len(data) != length:
        raise FieldError("expected %d, found %d" % (length, len(data)))
    return data

def _write_stream(stream, length, data):
    if length < 0:
        raise ValueError("length must be >= 0", length)
    if len(data) != length:
        raise FieldError("expected %d, found %d" % (length, len(data)))
    stream.write(data)


def UBInt24(name):
    """Unsigned, big endian 24-bit integer"""
    return IntField(name, 3, 'big', False)

def SBInt24(name):
    """Signed, big endian 24-bit integer"""
    return IntField(name, 3, 'big', True)


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
    def _decode(self, obj, context):
        return float(obj)/2**20
    def _encode(self, obj, context):
        return int(obj*2**20)


class TransformMatrix(Adapter):
    """ Converts an array of integers from and to a matrix of floats.

    Xetex's pic_file command includes a transformation matrix for the
    image.  The code to read it is in xdvipdfmx's dvi.c in
    do_pic_file() on lines 1978-1843, with the comment, "transform is
    a 3x2 affine transform matrix expressed in fixed-point values."
    This Adapter wraps an Array of integers.
    """
    def _decode(self, obj, context):
        return [[float(obj[0])/2**16, float(obj[1])/2**16],
                [float(obj[2])/2**16, float(obj[3])/2**16],
                [float(obj[4])/2**16, float(obj[5])/2**16]]
    def _encode(self, obj, context):
        return [int(obj[0][0]*2**16), int(obj[0][1]*2**16),
                int(obj[1][0]*2**16), int(obj[1][1]*2**16),
                int(obj[2][0]*2**16), int(obj[2][1]*2**16)]


class VFDVIAdapter(Adapter):
    """ Converts DVI code to and from a container.

    VF files embed DVI code to typeset characters.  When included in a
    Construct, this Adapter instantiates a class with the necessary
    dictionary to process the DVI opcodes that can appear in VF files
    and uses that class's read_bytes and write_bytes methods to turn
    DVI code into a list of containers representing the DVI commands
    and vice versa.  These methods read all the DVI code for one
    character into memtory, and theoretically a VF file could contain
    up to 2^31 - 1 bytes (~4 GB) of DVI code for a single character.
    In practice, typesetting a single character should never require
    more than a couple dozen bytes of DVI code at the absolute
    maximum.  This Adapter wraps a bytes string.

    Note that Constructs including this Adapter must be instantiated
    inside a class or otherwise things break.
    """
    __slots__ = ['_translator']

    def __init__(self, *args, **kwargs):
        """ Instantiates the DVI translator and calls the parent init.

        The parent's __init__ must be called after the translator is
        instantiated, I assume because either Subconstruct or
        Construct do something with __slots__ that breaks if
        _translator isn't defined yet.
        """
        self._translator = VFDVITranslator()
        Adapter.__init__(self, *args, **kwargs)

    def _decode(self, obj, context):
        return self._translator.read_bytes(obj)

    def _encode(self, obj, context):
        return self._translator.write_bytes(obj)


class PrintContext(Construct):
    """ Debugging code
    """
    def _parse(self, stream, context):
        print(context)


def PacketSwitch(name, opcodes):
    """
    When using Switch with a dictionary of Structs, what happens is
    that the Switch's name *replaces* the names of each Struct in the
    dictionary.  This means that the names of the inner Structs are
    meaningless and might as well be None.

    What I've learned from working from Construct in these cases is
    that I don't understand how Embed() works.  I basically hacked
    until I found something that worked.  My original plan was to use
    the names of Structs to create a 'command' field in the parsed
    dictionary that I could then access to figure out where to send
    the parameters.  However, it's very arbitrary whether the name of
    a construct of any sort ends up in the final dictionary, though in
    general it doesn't: the names of the Constructs in the dictionary
    I was passing to Switch as a rule didn't.  I can Embed the Switch
    and that would merge the 'fields' dictionary into the top level,
    but that doesn't help with assigning opcodes to commands.  At
    parsing time, before the Switch executes, I can't use lambdas to
    access the name because the Structs in its dictionary aren't
    instantiated and thus don't have names I can access.  Even after
    they've been instantiated, there's nothing in the context
    dictionary that lists the names of the Structs, and there's no
    (easy) way for me to insert code in a Construct object such that
    it executes during parsing.  This really leaves only two workable
    methods: create an extra dictionary that maps opcodes to command
    names and use Value to insert that, or use Value in the Switch
    dictionary.  I prefer the latter because it avoids a superfluous
    dictionary.
    """
    return Struct(name,
                  UBInt8('opcode'),
                  Embed(Switch('fields',
                               lambda ctx: ctx.opcode, 
                               opcodes)))

def Packet(name, opcode, struct):
    return Struct(name,
                  Magic(opcode.to_bytes(1, 'big')),
                  Embed(struct))


def Command(name):
    return Value('command', lambda ctx: name)


# Opcode factory functions

def _zero_parameter_opcode(name):
    return lambda *unused_args: Struct(None, Command(name))

def _one_parameter_opcode(name, parameter):
    return lambda i, signed: Struct(None,
                                    Command(name),
                                    IntField(parameter, i, 'big', signed))

# Meta-opcode functions

def _opcode_mixed_quadruplet(opcodes, start, construct):
    for i in range(start, start + 4):
        if i == start + 3:
            signed = True
        else:
            signed = False
        opcodes[i] = construct(i - start + 1, signed)

def _opcode_signed_quadruplet(opcodes, start, construct):
    for i in range(start, start + 4):
        opcodes[i] = construct(i - start + 1, True)
    
def _opcode_signed_quintuplet(opcodes, start, name, parameter):
    opcodes[start] = _zero_parameter_opcode(name)()
    # opcodes[start] = Struct(None, Command(name))
    _opcode_signed_quadruplet(opcodes, start + 1, _one_parameter_opcode(name, parameter))

def _opcode_range(opcodes, start, stop, construct):
    for i in range(start, stop):
        opcodes[i] = construct(i)

def _union(*dicts):
    """ Combines a tuple of dictionaries into one dictionary. """
    union = {}
    for d in dicts:
        union.update(d)
    return union


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


# Shared opcodes

def FntDef(i, signed):
    return Struct(None,
                  Command('fnt_def'),
                  IntField('font_num', i, 'big', signed),
                  SBInt32('checksum'),
                  FixWord(SBInt32('scale_factor')),
                  FixWord(SBInt32('design_size')),
                  UBInt8('a'),
                  UBInt8('l'),
                  String('tex_name', lambda ctx: ctx.a + ctx.l, 'ascii'))

_fnt_def_opcodes = {}
_opcode_mixed_quadruplet(_fnt_def_opcodes, 243, FntDef)


# VF opcodes

# _vf_opcodes = {}

def ShortChar(i):
    return Struct(None,
                  Command('short_char'),
                  UBInt8('char_code'),
                  FixWord(UBInt24('tfm_width')),
                  VFDVIAdapter(Field('dvi_code', i)))

# def VFPre():
#     return Struct(None,
#                   Command('pre'),
#                   Magic(b'\312'), 
#                   PascalString('comment', encoding = 'ascii'),
#                   SBInt32('checksum'),
#                   FixWord(SBInt32('design_size')))

def VFPre():
    return Struct(None,
                  Command('pre'),
                  Magic(b'\312'), 
                  PascalString('comment', encoding = 'ascii'),
                  SBInt32('checksum'),
                  FixWord(SBInt32('design_size')))


def VFPost():
    return Struct(None,
                  Command('post'),
                  Range(0, 3, Magic(b'\370')),
                  Terminator)

# _vf_opcodes[247] = VFPre()
# _vf_opcodes[248] = VFPost()


# DVI opcodes

_page_opcodes = {}

def FntNum(i):
    return Struct(None,
                  Command('fnt_num'),
                  Value('font_num', lambda ctx: ctx.opcode - 171))

def Xxx(i, signed):
    return Struct(None,
                  Command('xxx'),
                  PascalString('x', IntField('k', i, 'big', signed), 'ascii'))

def DVIPre(id_byte):
    return Struct(None,
                  Command('pre'),
                  Magic(id_byte),
                  SBInt32('numerator'),
                  SBInt32('denominator'),
                  SBInt32('magnification'),
                  PascalString('comment', encoding = 'ascii'))

def PostPost(id_byte):
    return Struct(None,
                  Command('post_post'),
                  SBInt32('q'),
                  Magic(id_byte),
                  Range(4, 7, Magic(b'\337')),
                  Terminator)

def Bop():
    return Struct(None,
                  Command('bop'),
                  Array(10, SBInt32('c')),
                  SBInt32('p'))

def DVIPost():
    return Struct(None,
                  Command('post'),
                  SBInt32('p'),
                  SBInt32('numerator'),
                  SBInt32('denominator'),
                  SBInt32('magnification'),
                  SBInt32('page_height_plus_depth'),
                  SBInt32('page_width'),
                  UBInt16('max_stack_depth'),
                  UBInt16('total_pages'))

_page_opcodes.update({132 : Struct(None,
                                  Command('set_rule'),
                                  SBInt32('height'),
                                  SBInt32('width')),
                     137 : Struct(None,
                                  Command('put_rule'),
                                  SBInt32('height'),
                                  SBInt32('width')),
                     138 : Pass,
                     # 139 : Bop(),
                     # 140 : Struct(None, Command('eop')),
                     141 : Struct(None, Command('push')),
                     142 : Struct(None, Command('pop')),
                     # 248: DVIPost()
                     })
# _page_opcodes.update(_fnt_def_opcodes)

_opcode_range(_page_opcodes, 0, 128, _zero_parameter_opcode('set_char'))
# _opcode_range(_page_opcodes, 0, 128, Struct(None, Command('set_char')))
_opcode_mixed_quadruplet(_page_opcodes, 128, _one_parameter_opcode('set',
                                                                  'char_code'))
_opcode_mixed_quadruplet(_page_opcodes, 133, _one_parameter_opcode('put',
                                                                  'char_code'))
_opcode_signed_quadruplet(_page_opcodes, 143, _one_parameter_opcode('right',
                                                                   'b'))
_opcode_signed_quintuplet(_page_opcodes, 147, 'w', 'b')
_opcode_signed_quintuplet(_page_opcodes, 152, 'x', 'b')
_opcode_signed_quadruplet(_page_opcodes, 157, _one_parameter_opcode('down', 'a'))
_opcode_signed_quintuplet(_page_opcodes, 161, 'y', 'a')
_opcode_signed_quintuplet(_page_opcodes, 166, 'z', 'a')
_opcode_range(_page_opcodes, 171, 235, FntNum)
_opcode_mixed_quadruplet(_page_opcodes, 235, _one_parameter_opcode('fnt',
                                                                  'font_num'))
_opcode_mixed_quadruplet(_page_opcodes, 239, Xxx)


# XDV opcodes

_xdv_opcodes = {}

def SetGlyph(name, construct):
    return Struct(None,
                  Command('set_glyph_' + name),
                  SBInt32('width'),
                  UBInt16('glyph_count'),
                  Array(lambda ctx: ctx.glyph_count, construct),
                  Array(lambda ctx: ctx.glyph_count,
                        UBInt16('glyph_id')))

def DefineNativeFont():
    return Struct(None,
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
                  UBInt8('lenps'),
                  UBInt8('lenfam'),
                  UBInt8('lensty'),
                  String('ps_name',
                         lambda ctx: ctx.lenps,
                         'ascii'),
                  String('family',
                         lambda ctx: ctx.lenfam,
                         'ascii'),
                  String('style',
                         lambda ctx: ctx.lensty,
                         'ascii'),
                  If(lambda ctx: ctx.colored,
                     UBInt32('rgba')),
                  If(lambda ctx: ctx.extend_flag,
                     SBInt32('extend')),
                  If(lambda ctx: ctx.slant_flag,
                     SBInt32('slant')),
                  If(lambda ctx: ctx.embolden_flag,
                     SBInt32('embolden')),
                  If(lambda ctx: ctx.variations,
                     Embed(Struct(None,
                                  UBInt16('nv'),
                                  Array(lambda ctx: ctx.nv,
                                        SBInt32('axes')),
                                  Array(lambda ctx: ctx.nv,
                                        SBInt32('values'))))))

_xdv_opcodes[251] = Struct(None,
                           Command('pic_file'),
                           # TODO: This needs some commenting
                           # to explain what this byte is,
                           # see 1994 of dvi.c
                           UBInt8('pdf_box'),
                           TransformMatrix(Array(6,
                                                 SBInt32('transform_matrix'))),
                           UBInt16('page_number'),
                           PascalString('path', UBInt16('length'), 'ascii'))
_xdv_opcodes[252] = DefineNativeFont()
_xdv_opcodes[253] = SetGlyph('array', Struct('loc',
                                             SBInt32('x'),
                                             SBInt32('y')))
_xdv_opcodes[254] = SetGlyph('string', SBInt32('xloc'))


def DVIFormat(id_byte, between_pages_opcodes, in_page_opcodes):
    return Struct(None,
                  Packet('pre', 247, DVIPre(id_byte)),
                  OptionalGreedyRange(PacketSwitch('before_pages', between_pages_opcodes)),
                  # The names in a Sequence are meaningless, but for
                  # some reason they can't be None, so I used
                  # one-element strings.
                  OptionalGreedyRange(Sequence('page',
                                               Packet('a', 139, Bop()),
                                               OptionalGreedyRange(PacketSwitch('b', in_page_opcodes)),
                                               Packet('c', 140, Struct(None, Command('eop'))),
                                               OptionalGreedyRange(PacketSwitch('d', between_pages_opcodes)))),
                  Packet('post', 248, DVIPost()),
                  OptionalGreedyRange(PacketSwitch('fonts', between_pages_opcodes)),
                  Packet('post_post', 249, PostPost(id_byte)))


# def VFFormat():
#     return Struct(None,
#                   Packet(_vf_pre()),
#                   OptionalGreedyRange(PacketSwitch(_fnt_def_opcodes)),
#                   OptionalGreedyRange(PacketSwitch(_char_opcodes)),
#                   Packet(_vf_post()))


class DVILikeTranslator:
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
    def __init__(self, data = b''):
        raise NotImplementedError
#        self.load(data)
#        self._opcodes = {}
#        self._file = GreedyRange(PacketSwitch(None, self._opcodes))

    def __iter__(self):
        return self

    def __next__(self):
        if self._end == self._buffer.tell():
            self._buffer.seek(0,0)
            raise StopIteration
        return PacketSwitch(None, self._opcodes).parse_stream(self._buffer)

    def load(self, data):
        if all([hasattr(data, attr) for attr in ['read', 'seek', 'tell']]):
            self._buffer = data
        else:
            self._buffer = io.BytesIO(data)
        self._end = self._buffer.seek(0, 2)
        self._buffer.seek(0, 0)
    
    def read_file(self, infile):
        return self._file.parse_stream(infile)

    def read_bytes(self, inmemory):
        return self._file.parse(inmemory)

    def write_file(self, container, outfile):
        return self._file.build_stream(container, outfile)

    def write_bytes(self, container):
        return self._file.build(container)



class VFTranslator(DVILikeTranslator):
    def __init__(self, data = b''):
        # DVILikeTranslator.__init__(self, data)
        self.load(data)
        self._char_opcodes = {}
        self._char_opcodes[242] = Struct(None,
                                         Command('long_char'),
                                         SBInt32('dvi_length'),
                                         SBInt32('char_code'),
                                         FixWord(SBInt32('tfm_width')),
                                         VFDVIAdapter(Field('dvi_code',
                                                            lambda ctx: ctx.dvi_length)))
        _opcode_range(self._char_opcodes, 0, 242, ShortChar)
        self.state = 'start'
        self._file = Struct(None,
                            Packet('pre', 247, VFPre()),
                            OptionalGreedyRange(PacketSwitch('fonts', _fnt_def_opcodes)),
                            OptionalGreedyRange(PacketSwitch('chars', self._char_opcodes)),
                            Packet('post', 248, VFPost()))
        self._opcodes0 = {}
        self._opcodes0.update(_fnt_def_opcodes)
        self._opcodes0.update(self._char_opcodes)
        self._opcodes1 = {}
        self._opcodes1.update(self._char_opcodes)
        self._opcodes1[248] = VFPost()
        self._state0 = PacketSwitch(None, self._opcodes0)
        self._state1 = PacketSwitch(None, self._opcodes1)

#    def __next__(self):
        
    def test(self):
        yield Packet(None, 247, VFPre()).parse_stream(self._buffer)
        while True:
            packet = self._state0.parse_stream(self._buffer)
            yield packet
            if packet.command != 'fnt_def':
                break
        while True:
            packet = self._state1.parse_stream(self._buffer)
            yield packet
            if packet.command == 'post':
                self._buffer.seek(0,0)
                return


#            if packet.command != 'short_char' and packet.command != 'long_char':
#                break
#        while True:
#            packet = PacketSwitch(None, self._opcodes2).parse_stream(self._buffer)

        # if self.state == 'start':
        #     self.state = 'fnt_defs'
        #     return Packet('pre', 247, VFPre()).parse_stream(self._buffer)
        # elif self.state == 'fnt_defs':
        #     packet = PacketSwitch(None, self._opcodes0).parse_stream(self._buffer)
        #     if packet.command == 'fnt_def':
        #         return packet
        #     elif packet.command == 'short_char' or packet.command == 'long_char':
        #         self.state = 'chars'
        #         return packet
        #     else:
        #         # TODO
        #         raise ValueError
        # elif self.state == 'chars':
        #     return PacketSwitch(None, self._opcodes1).parse_stream(self._buffer)


class VFDVITranslator(DVILikeTranslator):
    def __init__(self, data = b''):
        # DVILikeTranslator.__init__(self, data)
        self.load(data)
        # Opcodes 250-255 aren't allowed either but aren't defined in DVI
        self._opcodes = _page_opcodes
        self._file = GreedyRange(PacketSwitch(None, self._opcodes))


class DVITranslator(DVILikeTranslator):
    def __init__(self, data = b''):
        # DVILikeTranslator.__init__(self, data)
        self.load(data)
        self._id_byte = b'\2'        
        # self._opcodes.update(_dvi_opcodes)
        # self._opcodes[247] = DVIPre(self._id_byte)
        # self._opcodes[249] = PostPost(self._id_byte)
        self._post_opcodes = {}
        self._post_opcodes.update(_fnt_def_opcodes)
        # _opcode_mixed_quadruplet(self._post_opcodes, 243, FntDef)
        self._post_opcodes[138] = Pass
        self._page_opcodes = {}
        self._page_opcodes.update(_page_opcodes)
        self._page_opcodes.update(_fnt_def_opcodes)
        # self._page_opcodes[247] = self.__opcodes[247]
        # self._page_opcodes[249] = self.__opcodes[249]
        # _opcode_mixed_quadruplet(self._page_opcodes, 243, FntDef)
        self.state = 'start'
        self._file = DVIFormat(self._id_byte, self._post_opcodes, self._page_opcodes)
        self._opcodes0 = {}
        self._opcodes0.update(self._post_opcodes)
        self._opcodes0[139] = Bop()
        self._opcodes0[248] = DVIPost()
        self._opcodes1 = {}
        self._opcodes1.update(self._page_opcodes)
        self._opcodes1[140] = Struct(None, Command('eop'))
        self._opcodes2 = {}
        self._opcodes2.update(self._opcodes0)
        del self._opcodes2[248]
        self._opcodes2[249] = PostPost(self._id_byte)
        self._state0 = PacketSwitch(None, self._opcodes0)
        self._state1 = PacketSwitch(None, self._opcodes1)
        self._state2 = PacketSwitch(None, self._opcodes2)

    def __next__(self):
        pass

    def test(self):
        yield Packet(None, 247, DVIPre(self._id_byte)).parse_stream(self._buffer)
        while True:
            while True:
                packet = self._state0.parse_stream(self._buffer)
                yield packet
                if packet is not None and (packet.command == 'bop' or packet.command == 'post'):
                    break
            while packet.command != 'post':
                packet = self._state1.parse_stream(self._buffer)
                yield packet
                if packet.command == 'eop':
                    break
            if packet.command == 'post':
                break
        while True:
            print(packet.command)
            packet = self._state2.parse_stream(self._buffer)                
            yield packet
            if packet is not None and packet.command == 'post_post':
                self._buffer.seek(0,0)
                return

#        if self.state == 'start':
#            self.state = 'between_pages'
#            return Packet(None, 247, DVIPre(self._id_byte)).parse_stream(self._buffer)
#        elif self.state == 'between_pages':
#            packet = PacketSwitch(None, self._opcodes0).parse_stream(self._buffer)
#            if packet.command == 'fnt_def':
#                return packet
#            elif packet is None:
#                pass
#            elif packet.command == 'bop':
#                self.state = 'in_page'
#                return packet
#            elif packet.command == 'post':
#                self.state = 'fnt_defs'
#                return packet
#            elif self.state == 'in_page':
#                packet = self.PacketSwitch(None, self._opcodes1).parse_stream(self._buffer)
#                if packet.command == 'eop':
#                    self.state = 'between_pages'
#                    return packet
#                else:
#                    return packet
#            elif self.state == 'fnt_defs':
#                packet = PacketSwitch(None, self._opcodes2).parse_stream(self._buffer)
#                if packet.command == 'fnt_def':
#                    return packet
#                elif packet is None:
#                    pass
#                elif packet.command == 'post_post':
#                    return packet

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
            yield RepeatUntil(lambda obj, ctx: obj.command == 'eop', PacketSwitch(None, self._page_opcodes)).parse_stream(self._buffer)


class DVIVTranslator(DVITranslator):
    def __init__(self, data = b''):
        DVITranslator.__init__(self, data)
        self._id_byte = b'\3'
        self._page_opcodes[255] = Struct(None, Command('dir'), Flag('dir'))
        self._file = DVIFormat(self._id_byte, self._post_opcodes, self._page_opcodes)
        self._opcodes0[248] = DVIPost()
        self._opcodes1[255] = Struct(None, Command('dir'), Flag('dir'))
        self._opcodes2[249] = PostPost(self._id_byte)


class XDVTranslator(DVIVTranslator):
    def __init__(self, data = b''):
        DVIVTranslator.__init__(self, data)
        self._id_byte = b'\5'
        self._page_opcodes.update(_xdv_opcodes)
        self._post_opcodes[252] = DefineNativeFont()
        self._file = DVIFormat(self._id_byte, self._post_opcodes, self._page_opcodes)
        self._opcodes0[248] = DVIPost()
        self._opcodes0[252] = DefineNativeFont()
        self._opcodes1.update(_xdv_opcodes)
        self._opcodes2[249] = PostPost(self._id_byte)
        self._opcodes2[252] = DefineNativeFont()

# http://stackoverflow.com/questions/2101961/python-state-machine-design#answer-2102001

# http://code.activestate.com/recipes/146262-finite-state-machine-fsm/

# https://wiki.python.org/moin/State%20Machine%20via%20Decorators

# https://github.com/oxplot/fysom

# http://www.ibm.com/developerworks/linux/library/l-python-state/index.html

# 7http://www.ibm.com/developerworks/linux/library/l-pygen/index.html

# http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-01sc-introduction-to-electrical-engineering-and-computer-science-i-spring-2011/unit-1-software-engineering/state-machines/MIT6_01SCS11_chap04.pdf


class DVILikeMachine:
    def __init__(self, events, transitions, actions):
        """
        events: Dictionary mapping commands (strings) to events
        (strings) for the state machine.  All commands the state
        machine accepts must be keys in this dictionary.  Passing any
        command not in this dictionary to the state machine will cause
        it to raise an exception.

        transitions: Dictionary mapping events (strings) to
        dictionaries mapping states (strings) to states (strings).

        actions: Dictionary mapping (strings) of commands
        (strings) to actions (methods).  The default method for a
        command is the method with the same name as the command---this
        dictionary allows you to override that.  If a method doesn't
        exist, the default method is called instead.  The default for
        the default method is to do nothing, but this can also be
        overriden.
        """
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


# file = 'DroidSerif-Regular-ot1.vf'
file = 'extending_hardys_proof.dvi'
# file = 'testsuite/F-alias-feature-option.xdv'
# file = '02_xits_fonts.xdv'

with open(file, 'rb') as f:
    # for x in VFTranslator(f):
    # for x in DVITranslator(f):
    # for x in XDVTranslator(f):
    # for x in VFTranslator(f).test():
    for x in DVITranslator(f).test():
        print(x)
    # test = VFTranslator(f)
    # test = DVITranslator(f)
    # test = XDVTranslator(f)
    # print(test.read_file(f))
    # print(test.postamble())
    # i = 0
    # for x in test.pages():
    #     i = i + 1
    #     print('Page ' + str(i))
    #     for y in x:
    #         print(y)

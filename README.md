## Synopsis

This is a Python library for parsing and unparsing TeX binary files
like DVI, VF, and XDV files.

## Code Example

There are five classes in the external API:

* DVILikeProcessor: This is an abstract class never to be
  instantiated.  It has a class method, process(), that takes an input
  file and automatically returns an instance of the appropriate class
  for processing that file presuming the file is correctly formed.

* DVIProcessor, VFProcessor, and XDVProcessor: Classes corresponding
  to the file types in question.  Instantiate a class with
  FooProcessor(<file>), or use the load() method to load a file into
  an existing instance.  read_file() and write_file() will parse an
  entire file into memory or unparse an in-memory parse tree into a
  file; read_bytes() and write_bytes() do the same thing only to an
  in-memory binary representation of a file.  Iterating over any class
  instance will return the individual packets in the file one at a
  time.  DVIProcessor.pages() will return an iterator over the pages
  of the DVI file, in reverse order.  In the parse tree, each
  individual packet is represented by a mapping that gives the name of
  each variable in a packet and the value for that name.  The packets
  themselves or groups of packets, like the pages in a DVI file, are
  returned as a sequence or an iterator.  The write commands take the
  same kind of parse tree and turn it into a binary representation.
  PKProcessor exists but is an unimplemented stub at the moment.

* OpcodeCommandsMachine is a skeleton class designed for creating
  finite state machines that interpret the packets in a TeX binary
  file.  To implement such a machine, subclass OpcodeCommandsMachine
  and override the methods corresponding to the names of possible
  commands, create an instance, and then feed it packets one at a time
  by calling the instance on each packet.

## Motivation

This implementation provides a clean separation of the process of
parsing and unparsing TeX binary files and performing other operations
on them.  By returning a programmatic representation of the parse
tree, it's possible to build any kind of TeX binary processor on top
of this library.  It also handles VF and XDV files, which have no
existing implementations in Python at all as far as I know.

## Installation

The parser itself is a single script, dvilike.py.  It requires the
Construct binary parsing library
(https://pypi.python.org/pypi/construct).

## License

MIT.

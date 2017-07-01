import argparse
import struct
import sys

parser = argparse.ArgumentParser(description='Decompile ELF executable')
parser.add_argument('exe', help='ELF executable to decompile')

args = parser.parse_args()

EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EI_PAD = 9
E_TYPE = 16
E_MACHINE = 18
E_VERSION = 20
E_ENTRY = 24

class Field(object):
    def __init__(self, offset, size):
        self._offset = offset
        self._size = size

    @property
    def offset(self):
        return self._offset

    @property
    def size(self):
        return self._size


class Fields(object):
    @property
    def magic_number(self):
        return Field(0, 1)

    @property
    def magic_elf(self):
        return Field(1, 3)

    @property
    def bit_width(self):
        return Field(4, 1)

    @property
    def endianness(self):
        return Field(5, 1)

    @property
    def version(self):
        return Field(6, 1)

    @property
    def os_abi(self):
        return Field(7, 1)

    @property
    def abi_version(self):
        return Field(8, 1)

    @property
    def padding(self):
        return Field(9, 7)

    @property
    def type(self):
        return Field(16, 2)

    @property
    def machine(self):
        return Field(18, 2)

    @property
    def version2(self):
        return Field(20, 4)


class ThirtyTwoBitFields(Fields):
    @property
    def entry_point(self):
        return Field(24, 4)

    @property
    def program_headers_offset(self):
        return Field(28, 4)

    @property
    def section_headers_offset(self):
        return Field(32, 4)

    @property
    def flags(self):
        return Field(36, 4)

    @property
    def header_size(self):
        return Field(40, 2)


class SixtyFourBitFields(Fields):
    @property
    def entry_point(self):
        return Field(24, 8)

    @property
    def program_headers_offset(self):
        return Field(32, 8)

    @property
    def section_headers_offset(self):
        return Field(40, 8)

    @property
    def flags(self):
        return Field(48, 4)

    @property
    def header_size(self):
        return Field(52, 2)


class Elf(object):
    """
    See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    def __init__(self, bytes):
        self.bytes = bytes
        self._fields = Fields()
        if self.bit_width == 32:
            self._fields = ThirtyTwoBitFields()
        else:
            self._fields = SixtyFourBitFields()

    @property
    def magic_number(self):
        return self._get_unsigned_integer(self._fields.magic_number)

    @property
    def magic_elf(self):
        return self._get_string(self._fields.magic_elf)

    @property
    def bit_width(self):
        if ord(bytes[EI_CLASS]) == 1:
            return 32
        elif ord(bytes[EI_CLASS]) == 2:
            return 64 

    @property
    def endianness(self):
        if self._get_unsigned_integer(self._fields.endianness) == 1:
            return 'little'

        return 'big'

    @property
    def is_littleendian(self):
        return self.endianness == 'little'

    @property
    def is_bigendian(self):
        return not self.is_littleendian

    @property
    def version(self):
        return self._get_unsigned_integer(self._fields.version)

    @property
    def os_abi(self):
        abi = self._get_unsigned_integer(self._fields.os_abi)
        if abi == 0:
            return 'System V'
        elif abi == 1:
            return 'HP-UX'
        elif abi == 2:
            return 'NetBSD'
        elif abi == 3:
            return 'Linux'
        elif abi == 4:
            return 'GNU Hurd'
        elif abi == 6:
            return 'Solaris'
        elif abi == 7:
            return 'AIX'
        elif abi == 8:
            return 'IRIX'
        elif abi == 9:
            return 'FreeBSD'
        elif abi == 10:
            return 'Tru64'
        elif abi == 11:
            return 'Novell Modesto'
        elif abi == 12:
            return 'OpenBSD'
        elif abi == 13:
            return 'OpenVMS'
        elif abi == 14:
            return 'NonStop Kernel'
        elif abi == 15:
            return 'AROS'
        elif abi == 16:
            return 'Fenix OS'
        elif abi == 17:
            return 'CloudABI'
        elif abi == 83:
            return 'Sortix'
        else:
            return 'Unknown'

    @property
    def abi_version(self):
        return self._get_unsigned_integer(self._fields.abi_version)

    @property
    def padding(self):
        """
        Currently unused.
        """
        return self._get_string(self._fields.padding)

    @property
    def type(self):
        object_type = self._get_unsigned_integer(self._fields.type)
        if object_type == 1:
            return 'Relocatable'
        elif object_type == 2:
            return 'Executable'
        elif object_type == 3:
            return 'Shared'
        elif object_type == 4:
            return 'Core' 
        else:
            return 'Unknown'

    @property
    def machine(self):
        mach = self._get_unsigned_integer(self._fields.machine)
        if mach == 0x00:
            return 'None specified'
        elif mach == 0x02:
            return 'SPARC'
        elif mach == 0x03:
            return 'x86'
        elif mach == 0x08:
            return 'MIPS'
        elif mach == 0x14:
            return 'PowerPC'
        elif mach == 0x28:
            return 'ARM'
        elif mach == 0x2A:
            return 'SuperH'
        elif mach == 0x32:
            return 'IA-64'
        elif mach == 0x3E:
            return 'x86-64'
        elif mach == 0xB7:
            return 'AArch64'
        elif mach == '0xF3':
            return 'RISC-V'

    @property
    def version2(self):
        return self._get_unsigned_integer(self._fields.version2)

    @property
    def entry_point(self):
        return self._get_unsigned_integer(self._fields.entry_point)

    @property
    def program_headers_offset(self):
        return self._get_unsigned_integer(self._fields.program_headers_offset)

    @property
    def section_headers_offset(self):
        return self._get_unsigned_integer(self._fields.section_headers_offset)

    @property
    def flags(self):
        return self._get_unsigned_integer(self._fields.flags)

    @property
    def header_size(self):
        return self._get_unsigned_integer(self._fields.header_size)

    def _get_unsigned_integer(self, field):
        byte_count_indicators = {
            1: 'B', 2: 'H', 4: 'I', 8: 'Q'
        }

        return self._get_bytes(
            field.offset, byte_count_indicators[field.size])

    def _get_string(self, field):
        return self._get_bytes(field.offset, str(field.size) + 's')

    def _get_one_byte_unsigned_integer(self, start_index):
        return self._get_bytes(start_index, 'B')

    def _get_two_byte_unsigned_integer(self, start_index):
        return self._get_bytes(start_index, 'H')

    def _get_four_byte_unsigned_integer(self, start_index):
        return self._get_bytes(start_index, 'I')

    def _get_eight_byte_unsigned_integer(self, start_index):
        return self._get_bytes(start_index, 'Q')

    def _get_bytes(self, start_index, byte_count_indicator):
        direction = '<'
        if byte_count_indicator != 'B' and self.is_bigendian:
            direction = '>'

        return struct.unpack_from(direction + byte_count_indicator, self.bytes, start_index)[0]


exe = args.exe

bytes = ''
with open(exe, 'rb') as f:
    while True:
        byte_char = f.read(1)
        if byte_char == '':
            break

        bytes += byte_char


elf = Elf(bytes)
print('Magic number:\t\t' + '0x' + format(elf.magic_number, '02X') + ' \'' + elf.magic_elf + '\'')
print('Bit width:\t\t' + str(elf.bit_width))
print('Endianness:\t\t' + elf.endianness)
print('Version:\t\t' + str(elf.version))
print('OS ABI:\t\t\t' + elf.os_abi)
print('ABI version:\t\t' + str(elf.abi_version))
print('Type:\t\t\t' + elf.type)
print('Instruction set:\t' + elf.machine)
print('Version (2):\t\t' + str(elf.version2))
print('Entry point:\t\t' + '0x' + format(elf.entry_point, '02X'))
print('Program headers start:\t' + str(elf.program_headers_offset) + ' (bytes into the file)')
print('Section headers start:\t' + str(elf.section_headers_offset) + ' (bytes into the file)')
print('Flags:\t\t\t' + str(elf.flags))
print('Size of this header:\t' + str(elf.header_size) + ' (bytes)')

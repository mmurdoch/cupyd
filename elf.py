import argparse
import inspect
import struct

parser = argparse.ArgumentParser(description='Decompile ELF executable')
parser.add_argument('exe', help='ELF executable to decompile')

args = parser.parse_args()

def _get_field(fields, bytes, elf):
    calling_method_name = inspect.stack()[2][3]
    field = getattr(fields, calling_method_name)
    if field.size == 1 or field.size % 2 == 0:
        return _get_unsigned_integer(field, bytes, elf)

    return _get_string(field, bytes, elf)

def _get_unsigned_integer(field, bytes, elf):
    byte_count_indicators = {
        1: 'B', 2: 'H', 4: 'I', 8: 'Q'
    }

    return _get_bytes(field.offset,
        byte_count_indicators[field.size], bytes, elf)

def _get_string(field, bytes, elf):
    return _get_bytes(field.offset,
        str(field.size) + 's', bytes, elf)

def _get_bytes(start_index, byte_count_indicator, bytes, elf):
    direction = '<'
    if byte_count_indicator != 'B' and elf.is_bigendian:
        direction = '>'

    return struct.unpack_from(direction + byte_count_indicator,
        bytes, start_index)[0]


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


class FileHeaderFields(object):
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


class ThirtyTwoBitFileHeaderFields(FileHeaderFields):
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

    @property
    def program_header_entry_size(self):
        return Field(42, 2)

    @property
    def program_header_entry_count(self):
        return Field(44, 2)

    @property
    def section_header_entry_size(self):
        return Field(46, 2)

    @property
    def section_header_entry_count(self):
        return Field(48, 2)

    @property
    def section_header_name_section_index(self):
        return Field(50, 2)


class SixtyFourBitFileHeaderFields(FileHeaderFields):
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

    @property
    def program_header_entry_size(self):
        return Field(54, 2)

    @property
    def program_header_entry_count(self):
        return Field(56, 2)

    @property
    def section_header_entry_size(self):
        return Field(58, 2)

    @property
    def section_header_entry_count(self):
        return Field(60, 2)

    @property
    def section_header_name_section_index(self):
        return Field(62, 2)


class SectionHeaderFields(object):
    @property
    def name_string_offset(self):
        return Field(0, 4)

    @property
    def type(self):
        return Field(4, 4)


class ThirtyTwoBitSectionHeaderFields(SectionHeaderFields):
    @property
    def flags(self):
        return Field(8, 4)

    @property
    def address(self):
        return Field(12, 4)

    @property
    def offset(self):
        return Field(16, 4)

    @property
    def size(self):
        return Field(20, 4)

    @property
    def linked_section_index(self):
        return Field(24, 4)

    @property
    def info(self):
        return Field(28, 4)

    @property
    def alignment(self):
        return Field(32, 4)

    @property
    def entry_size(self):
        return Field(36, 4)


class SixtyFourBitSectionHeaderFields(SectionHeaderFields):
    @property
    def flags(self):
        return Field(8, 8)

    @property
    def address(self):
        return Field(16, 8)

    @property
    def offset(self):
        return Field(24, 8)

    @property
    def size(self):
        return Field(32, 8)

    @property
    def linked_section_index(self):
        return Field(40, 4)

    @property
    def info(self):
        return Field(44, 4)

    @property
    def alignment(self):
        return Field(48, 8)

    @property
    def entry_size(self):
        return Field(56, 8)


class SectionHeader(object):
    def __init__(self, fields, bytes, elf):
        self._fields = fields
        self._bytes = bytes
        self._elf = elf

    @property
    def name_string_offset(self):
        return self._get_field()

    @property
    def name(self):
        return elf.section_header_names.string_at(self.name_string_offset)

    @property
    def type(self):
        section_type = self._get_field() 
        if section_type == 0:
            return 'NULL'
        elif section_type == 1:
            return 'PROGBITS'
        elif section_type == 2:
            return 'SYMTAB'
        elif section_type == 3:
            return 'STRTAB'
        elif section_type == 4:
            return 'RELA'
        elif section_type == 5:
            return 'HASH'
        elif section_type == 6:
            return 'DYNAMIC'
        elif section_type == 7:
            return 'NOTE'
        elif section_type == 8:
            return 'NOBITS'
        elif section_type == 9:
            return 'REL'
        elif section_type == 10:
            return 'SHLIB'
        elif section_type == 11:
            return 'DYNSYM'
        elif section_type == 14:
            return 'INIT_ARRAY'
        elif section_type == 15:
            return 'FINI_ARRAY'
        elif section_type == 16:
            return 'PREINIT_ARRAY'
        elif section_type == 17:
            return 'GROUP'
        elif section_type == 18:
            return 'SYMTAB_SHNDX'
        elif section_type == 19:
            return 'NUM'
        else:
            return str(section_type) + ' ? '

    @property
    def flags(self):
        return self._get_field()

    @property
    def address(self):
        return self._get_field()

    @property
    def offset(self):
        return self._get_field()

    @property
    def size(self):
        return self._get_field()

    @property
    def linked_section_index(self):
        return self._get_field()

    @property
    def info(self):
        return self._get_field()

    @property
    def alignment(self):
        return self._get_field()

    @property
    def entry_size(self):
        return self._get_field()

    def _get_field(self):
        return _get_field(self._fields, self._bytes, self._elf)


class StringTable(object):
    def __init__(self, bytes):
        self._bytes = bytes

    def string_at(self, offset):
        string = ''

        current_index = offset
        while ord(self._bytes[current_index]) != 0:
            string += self._bytes[current_index]
            current_index += 1

        return string

    @property
    def entries(self):
        strings = []

        string = ''
        for byte in self._bytes:
            if ord(byte) == 0:
                strings.append(string)
                string = ''
            else:
                string += byte
 
        return strings


class SymbolTableFields(object):
    @property
    def name_string_offset(self):
        return Field(0, 4)


class ThirtyTwoBitSymbolTableFields(SymbolTableFields):
    @property
    def value(self):
        return Field(4, 4)

    @property
    def info(self):
        return Field(12, 1)

    @property
    def section_table_index(self):
        return Field(14, 2)

    @property
    def total_size(self):
        return 16


class SixtyFourBitSymbolTableFields(SymbolTableFields):
    @property
    def value(self):
        return Field(8, 8)

    @property
    def info(self):
        return Field(4, 1)

    @property
    def section_table_index(self):
        return Field(6, 2)

    @property
    def total_size(self):
        return 24


class Symbol(object):
    def __init__(self, fields, bytes, elf):
        self._fields = fields
        self._bytes = bytes
        self._elf = elf

    @property
    def name_string_offset(self):
        return self._get_field()

    @property
    def name(self):
        return elf.string_table.string_at(self.name_string_offset)

    @property
    def value(self):
        return self._get_field()

    @property
    def info(self):
        return self._get_field()

    @property
    def type(self):
        t = self.info & 15
        if t == 0:
            return 'NOTYPE'
        elif t == 1:
            return 'OBJECT'
        elif t == 2:
            return 'FUNC'
        elif t == 3:
            return 'SECTION'
        elif t == 4:
            return 'FILE'
        else:
            return 'Unknown'

    @property
    def section_table_index(self):
        return self._get_field()

    @property
    def section_name(self):
        index = self.section_table_index
        if index == 0:
            return 'UNDEF'
        elif index == 65521:
            return 'ABS'
        elif index == 65522:
            return 'COMMON'
        else:
            return self._elf.section_headers[index].name

    def _get_field(self):
        return _get_field(self._fields, self._bytes, self._elf)


class SymbolTable(object):
    def __init__(self, fields, bytes, elf):
        self._fields = fields
        self._bytes = bytes
        self._elf = elf 

    @property
    def entries(self):
        symbols = []

        for i in range(0, len(self._bytes), self._fields.total_size):
            bytes = self._bytes[i:i+self._fields.total_size]
            symbols.append(Symbol(self._fields, bytes, self._elf))

        return symbols


class Elf(object):
    """
    See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    def __init__(self, bytes):
        self._bytes = bytes
        self._file_header_fields = FileHeaderFields()
        if self.bit_width == 32:
            self._file_header_fields = ThirtyTwoBitFileHeaderFields()
            self._section_header_fields = ThirtyTwoBitSectionHeaderFields()
            self._symbol_table_fields = ThirtyTwoBitSymbolTableFields()
        else:
            self._file_header_fields = SixtyFourBitFileHeaderFields()
            self._section_header_fields = SixtyFourBitSectionHeaderFields()
            self._symbol_table_fields = SixtyFourBitSymbolTableFields()

    @property
    def magic_number(self):
        return self._get_file_header_field()

    @property
    def magic_elf(self):
        return self._get_file_header_field()

    @property
    def bit_width(self):
        if self._get_file_header_field() == 1:
            return 32

        return 64 

    @property
    def endianness(self):
        if self._get_file_header_field() == 1:
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
        return self._get_file_header_field()

    @property
    def os_abi(self):
        abi = self._get_file_header_field()
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
        return self._get_file_header_field()

    @property
    def padding(self):
        """
        Currently unused.
        """
        return self._get_file_header_field()

    @property
    def type(self):
        object_type = self._get_file_header_field()
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
        mach = self._get_file_header_field()
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
        return self._get_file_header_field()

    @property
    def entry_point(self):
        return self._get_file_header_field()

    @property
    def program_headers_offset(self):
        return self._get_file_header_field()

    @property
    def section_headers_offset(self):
        return self._get_file_header_field()

    @property
    def flags(self):
        return self._get_file_header_field()

    @property
    def header_size(self):
        return self._get_file_header_field()

    @property
    def program_header_entry_size(self):
        return self._get_file_header_field()

    @property
    def program_header_entry_count(self):
        return self._get_file_header_field()

    @property
    def section_header_entry_size(self):
        return self._get_file_header_field()

    @property
    def section_header_entry_count(self):
        return self._get_file_header_field()

    @property
    def section_header_name_section_index(self):
        return self._get_file_header_field()

    def _get_file_header_field(self):
        return _get_field(self._file_header_fields, self._bytes, self)

    @property
    def section_headers(self):
        if not hasattr(self, '_section_headers'):
            section_headers = []

            for i in range(self.section_header_entry_count):
                start = self.section_headers_offset + i*self.section_header_entry_size
                end = start + self.section_header_entry_size
                bytes = self._bytes[start:end]
                fields = self._section_header_fields
                section_headers.append(SectionHeader(fields, bytes, self)) 
            self._section_headers = section_headers

        return self._section_headers

    @property
    def section_header_names(self):
        if not hasattr(self, '_section_header_names'):
            header = elf.section_headers[elf.section_header_name_section_index]

            start = header.offset
            end = start + header.size
            bytes = self._bytes[start:end]
            self._section_header_names = StringTable(bytes)
        return self._section_header_names

    @property
    def string_table(self):
        if not hasattr(self, '_string_table'):
            self._string_table = None
            for header in self.section_headers:
                if header.name == '.strtab':
                    start = header.offset
                    end = start + header.size
                    bytes = self._bytes[start:end]
                    self._string_table = StringTable(bytes)
                    break
        return self._string_table

    @property
    def symbol_table(self):
        if not hasattr(self, '_symbol_table'):
            self._symbol_table = None
            for header in self.section_headers:
                if header.name == '.symtab':
                    start = header.offset
                    end = start + header.size
                    bytes = self._bytes[start:end]
                    fields = self._symbol_table_fields
                    self._symbol_table = SymbolTable(fields, bytes, self)
                    break
        return self._symbol_table


exe = args.exe

bytes = ''
with open(exe, 'rb') as f:
    while True:
        byte_char = f.read(1)
        if byte_char == '':
            break

        bytes += byte_char


elf = Elf(bytes)
print('Magic number:\t\t\t\t' + '0x' + format(elf.magic_number, '02X') + ' \'' + elf.magic_elf + '\'')
print('Bit width:\t\t\t\t' + str(elf.bit_width))
print('Endianness:\t\t\t\t' + elf.endianness)
print('Version:\t\t\t\t' + str(elf.version))
print('OS ABI:\t\t\t\t\t' + elf.os_abi)
print('ABI version:\t\t\t\t' + str(elf.abi_version))
print('Type:\t\t\t\t\t' + elf.type)
print('Instruction set:\t\t\t' + elf.machine)
print('Version (2):\t\t\t\t' + str(elf.version2))
print('Entry point:\t\t\t\t' + '0x' + format(elf.entry_point, '02X'))
print('Program headers start:\t\t\t' + str(elf.program_headers_offset) + ' (bytes into the file)')
print('Section headers start:\t\t\t' + str(elf.section_headers_offset) + ' (bytes into the file)')
print('Flags:\t\t\t\t\t' + str(elf.flags))
print('Size of this header:\t\t\t' + str(elf.header_size) + ' (bytes)')
print('Size of a program (segment) header:\t' + str(elf.program_header_entry_size) + ' (bytes)')
print('Number of program (segment) headers:\t' + str(elf.program_header_entry_count))
print('Size of a section header:\t\t' + str(elf.section_header_entry_size) + ' (bytes)')
print('Number of section headers:\t\t' + str(elf.section_header_entry_count))
print('Index of section names section header:\t' + str(elf.section_header_name_section_index))

print('\nSections')

def pad_to(string, width):
    while len(string) < width:
        string += ' '

    return string

print('Name\t\t\tType\t\tOffset\tSize\tVirtual Address')
for header in elf.section_headers:
    print(pad_to(header.name, 20) + '\t' + pad_to(str(header.type), 10) + '\t' + str(header.offset) + '\t' + str(header.size) + '\t0x' + format(header.address, '08X'))

print('\nString Table')
for string in elf.string_table.entries:
    print(string)

print('\nSymbol Table')
print('Value\t\t\tType\tSection\t\t\tName')
for symbol in elf.symbol_table.entries:
    print(format(symbol.value, '016X') + '\t' + symbol.type + '\t' + pad_to(symbol.section_name, 20) +'\t' + symbol.name)

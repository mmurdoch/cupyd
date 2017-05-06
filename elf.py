import argparse
import struct
import sys

parser = argparse.ArgumentParser(description='Decompile ELF executable')
parser.add_argument('--exe', help='ELF executable to decompile')

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

class Elf(object):
    """
    See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    def __init__(self, bytes):
        self.bytes = bytes

    @property
    def magic_number(self):
        return bytes[EI_MAG0]

    @property
    def magic_elf(self):
        return chr(bytes[EI_MAG1]) + chr(bytes[EI_MAG2]) + chr(bytes[EI_MAG3])

    @property
    def bit_width(self):
        if bytes[EI_CLASS] == 1:
            return 32
        elif bytes[EI_CLASS] == 2:
            return 64 

    @property
    def endianness(self):
        if bytes[EI_DATA] == 1:
            return 'little'
        elif bytes[EI_DATA] == 2:
            return 'big'

    @property
    def is_littleendian(self):
        return self.endianness == 'little'

    @property
    def is_bigendian(self):
        return not self.is_littleendian

    @property
    def version(self):
        return bytes[EI_VERSION]

    @property
    def os_abi(self):
        abi = bytes[EI_OSABI]
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
        return bytes[EI_ABIVERSION]

    @property
    def padding(self):
        """
        Currently unused.
        """
        return bytes[EI_PAD:EI_PAD+7]

    @property
    def type(self):
        object_type = bytes[E_TYPE+self._byte_offset(2)]

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
        mach = bytes[E_MACHINE+self._byte_offset(2)]
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
    def version(self):
        return bytes[E_VERSION+self._byte_offset(4)] 

    def _byte_offset(self, byte_count):
        byte_offset = 0
        if self.is_bigendian:
            byte_offset = byte_count-1

        return byte_offset


exe = args.exe
if not exe:
    print('You must specify an ELF file to examine using the --exe command line argument')
    sys.exit(1)

bytes = []
with open(exe, 'rb') as f:
    while True:
        byte_char = f.read(1)
        if byte_char == '':
            break

        byte = ord(byte_char)
        bytes.append(byte)


elf = Elf(bytes)
print('Magic number:\t\t' + '0x' + format(elf.magic_number, '02X') + ' \'' + elf.magic_elf + '\'')
print('Bit width:\t\t' + str(elf.bit_width))
print('Endianness:\t\t' + elf.endianness)
print('Version:\t\t' + str(elf.version))
print('OS ABI:\t\t\t' + elf.os_abi)
print('ABI version:\t\t' + str(elf.abi_version))
print('Type:\t\t\t' + elf.type)
print('Instruction set:\t' + elf.machine)
print('ELF version:\t\t' + str(elf.version))

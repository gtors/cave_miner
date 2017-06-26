from struct import pack
from typing import List
from .utils import *
from .formats import *

def search_cave(name: str, 
                body: List[str], 
                cave_size: int, 
                file_offset: int, 
                vaddr: int, 
                infos: str,
                _bytes: List[str]) -> None:

    null_count = 0

    for offset, byte in enumerate(body):
        if byte in _bytes:
            null_count += 1
        elif null_count >= cave_size:
            print(color("{yellow}[*]{bold} New cave detected !{endc}"))
            print(
                f"  section_name: {name}\n"
                f"  cave_begin:   0x{file_offset + offset - null_count:08x}\n"
                f"  cave_end:     0x{file_offset - offset:08x}\n"
                f"  cave_size:    0x{null_count:08x}\n"
                f"  vaddress:     0x{vaddr + offset - null_count:08x}\n"
                f"  infos:        {infos}\n\n"
            )
            null_count = 0
        else:
            null_count = 0


def parse_macho_flags(byte: int) -> str:
    ret = []

    if 0x1 & byte == 0x1:
        ret.append("READ")
    if 0x2 & byte == 0x2:
        ret.append("WRITE")
    if 0x4 & byte == 0x4:
        ret.append("EXECUTE")

    return ", ".join(ret)


def parse_sh_flags(byte: int) -> str:
    ret = []

    if 0x0000001 & byte == 0x0000001:
        ret.append("SHF_WRITE")
    if 0x0000002 & byte == 0x0000002:
        ret.append("SHF_ALLOC")
    if 0x0000004 & byte == 0x0000004:
        ret.append("SHF_EXECINSTR")
    if 0x0000010 & byte == 0x0000020:
        ret.append("SHF_MERGE")
    if 0x0000020 & byte == 0x0000020:
        ret.append("SHF_STRINGS")
    if 0x0000040 & byte == 0x0000040:
        ret.append("SHF_INFO_LINK")
    if 0x0000080 & byte == 0x0000080:
        ret.append("SHF_LINK_ORDER")
    if 0x0000100 & byte == 0x0000100:
        ret.append("SHF_OS_NONCONFORMING")
    if 0x0000200 & byte == 0x0000200:
        ret.append("SHF_GROUP")
    if 0x0000400 & byte == 0x0000400:
        ret.append("SHF_TLS")
    if 0xff00000 & byte == 0xff00000:
        ret.append("SHF_MASKOS")

    return ", ".join(ret)


def parse_pe_flags(byte: int) -> str:
    ret = []

    if 0x10000000 & byte == 0x10000000:
        ret.append("Shareable")
    if 0x20000000 & byte == 0x20000000:
        ret.append("Executable")
    if 0x40000000 & byte == 0x40000000:
        ret.append("Readable")
    if 0x80000000 & byte == 0x80000000:
        ret.append("Writeable")
    if 0x01000000 & byte == 0x01000000:
        ret.append("Contain extended relocation")
    if 0x02000000 & byte == 0x02000000:
        ret.append("Discardable as needed")
    if 0x04000000 & byte == 0x04000000:
        ret.append("Cant be cached")
    if 0x00001000 & byte == 0x00001000:
        ret.append("Contain COMDAT data")
    if 0x00000200 & byte == 0x00000200:
        ret.append("Contais comments or other infos")
    if 0x00000800 & byte == 0x00000800:
        ret.append("Wont become part of the image")
    if 0x00000020 & byte == 0x00000020:
        ret.append("Contain executable code")
    if 0x00000040 & byte == 0x00000040:
        ret.append("Contain initialized data")
    if 0x00000080 & byte == 0x00000080:
        ret.append("Contain uninitialized data")
    if 0x00000008 & byte == 0x00000008:
        ret.append("Shouldnt be padded to next boundary")

    return ", ".join(ret)


def search_pe(file_name: str, cave_sz: int, _bytes: List[str]) -> None:
    g = MicrosoftPe.from_file(file_name)

    if g.optional_hdr.std.format == MicrosoftPe.PeFormat.pe32:
        base_addr = g.optional_hdr.windows.image_base_32
    else:
        base_addr = g.optional_hdr.windows.image_base_64

    for section in g.sections:
        section_offset = section.pointer_to_raw_data
        infos = parse_pe_flags(section.characteristics)
        vaddr = section.virtual_address + base_addr
        search_cave(section.name, section.body, cave_sz,
                    section_offset, vaddr, infos, _bytes)


def search_macho(file_name: str, cave_sz: int, _bytes: List[str]) -> None:
    g = MachO.from_file(file_name)
    is_seg64 = MachO.LoadCommandType.segment_64.__eq__

    for command in filter(is_seg64, g.load_commands):
        for section in command.body.sections:
            if not isinstance(section.data, str):
                continue

            initprot = parse_macho_flags(command.body.initprot)
            maxprot = parse_macho_flags(command.body.maxprot)
            infos = f"init: [{initprot}], max: [{maxprot}]"

            search_cave(f"{section.seg_name}.{section.sect_name}",
                        section.data, cave_sz, section.offset, 
                        section.addr, infos, _bytes)


def search_elf(file_name: str, cave_sz: int, _bytes: List[str]) -> None:
    g = Elf.from_file(file_name)

    for section in g.header.section_headers:
        infos = parse_sh_flags(section.flags)
        search_cave(section.name, section.body, cave_sz,
                    section.offset, section.addr, infos, _bytes)


MAGIC_MZ = "MZ"
MAGIC_ELF = "\x7FELF"
MAGIC_MACHO = pack("I", 0xfeedfacf)


def detect_type(file_name: str, cave_sz: int, _bytes: List[str]) -> None:
    with open(file_name, "rb") as fh:
        data = fh.read()
        if data[0x0:0x2] == MAGIC_MZ:
            search_pe(file_name, cave_sz, _bytes)
        elif data[0x0:0x4] == MAGIC_ELF:
            search_elf(file_name, cave_sz, _bytes)
        elif data[0x0:0x4] == MAGIC_MACHO:
            search_macho(file_name, cave_sz, _bytes)


def search(file_name: str, cave_sz: str, bytes_arg: List[str]) -> None:
    print(color("{yellow}[*]{bold} Starting cave mining process...{endc}"))
    print(color(f"    {{bold}} Searching for bytes: {', '.join(bytes_arg)}...{{endc}}"))
    _bytes = [chr(int(e, 16)) for e in bytes_arg]
    detect_type(file_name, parse_int(cave_sz), _bytes)
    print(color("{yellow}[*]{bold} Mining finished{endc}"))

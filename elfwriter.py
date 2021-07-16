
# Small ELF writer targeted at producing CORE files
# Written by David Guillen Fandos <david@davidgf.net>

import struct

ET_NONE = 0
ET_REL  = 1
ET_EXEC = 2
ET_DYN  = 3
ET_CORE = 4
ET_NUM  = 5

EM_NONE = 0
EM_386 = 3
EM_68K = 4
EM_MIPS = 8
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6

NT_PRPSINFO = 3
NT_PRSTATUS = 1

def wrap_note(name, cid, content):
	ret = struct.pack("<III", len(name), len(content), cid) + name
	while len(ret) % 4:
		ret += b"\x00"
	ret += content
	while len(ret) % 4:
		ret += b"\x00"
	return ret	

class ElfFile(object):
	def __init__(self, e_type=ET_EXEC, e_machine=EM_NONE, e_flags=0, e_entry=0):
		self._e_type = e_type
		self._e_machine = e_machine
		self._e_entry = e_entry
		self._e_flags = e_flags
		self._phdrs = []

	def add_mem_block(self, pvaddr, ppaddr, pflags, data):
		self._add_program_header(PT_LOAD, pvaddr, ppaddr, pflags, data)

	def add_note_block(self, regs):
		# Add NT_PRPSINFO (3) with some fake info
		info1 = struct.pack("<BBBBIII", 0, 0, 0, 0, 0, 1000, 1000)
		info2 = struct.pack("<IIII", 1, 1, 1, 1)   # Pids/Gids
		info3 = b"ps2-executable\0\0" + (b"\x00" * 80)

		# Add NT_PRSTATUS (1) with register values
		status1 = struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)   # Signals
		status2 = struct.pack("<IIII", 1, 1, 1, 1) + (b"\0" * 32)  # Pids + Time
		status3 = regs + b"\0\0\0\0"

		data1 = wrap_note(b"CORE\0", NT_PRPSINFO, info1 + info2 + info3)
		data2 = wrap_note(b"CORE\0", NT_PRSTATUS, status1 + status2 + status3)
	
		self._add_program_header(PT_NOTE, 0, 0, 0, data1 + data2)

	def _add_program_header(self, ptype, pvaddr, ppaddr, pflags, data):
		self._phdrs.append({
			"type": ptype, "flags": pflags,
			"vaddr": pvaddr, "paddr": ppaddr, "data": data})

	def serialize(self):
		hdr1 = struct.pack("<HHIII", self._e_type, self._e_machine, 1, self._e_entry, 64)
		hdr2 = struct.pack("<IIHHHH", 0, self._e_flags, 0x34, 32, len(self._phdrs), 0)
		hdr3 = struct.pack("<HHIII", 0, 0, 0, 0, 0) # eshnum, eshstrndx

		# Serialize the program headers and their content too
		hdr4 = b""
		offset = 64 + 32 * len(self._phdrs)
		for i, prog in enumerate(self._phdrs):
			hdr4 += struct.pack("<IIIIIIII", prog["type"], offset, prog["vaddr"], prog["paddr"],
				len(prog["data"]), len(prog["data"]) if prog["type"] == PT_LOAD else 0, prog["flags"], 0)
			offset += len(prog["data"])

		# Header + 32bit ELF + little endian + version
		return (
			b"\x7FELF\x01\x01\x01\x00\x00\x00" +
			b"\x00\x00\x00\x00\x00\x00" +
			hdr1 + hdr2 + hdr3 + hdr4 +
			b"".join(x["data"] for x in self._phdrs))



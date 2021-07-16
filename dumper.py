#!/bin/env python3

# Copyright David Guillen Fandos <david@davidgf.net>
# This is a small program that will attempt to read a PCSX2 savestate and
# produce a core dump (ELF).

# Usage: dumper.py statefile output.elf

import sys, struct, zipfile
from elfwriter import *

# CpuRegs
#   32 MIPS regs (128b)
#    2 HILO regs (128b)
#   32 CP0  regs (32b)
#    1 sa   reg  (32b)
#    1 isds var  (32b)
#    1 PC   reg  (32b)

def strpad(bstr, sz):
	return bstr + (b"\x00" * (sz - len(bstr)))

class StateReader(object):
	def __init__(self, statefilepath):
		self._path = statefilepath
		self._off = 0

	def parse(self):
		with zipfile.ZipFile(self._path, "r") as fd:
			version = fd.read("PCSX2 Savestate Version.id")
			version = struct.unpack("<I", version)[0]
			# I think nothing has fundamentally changed since this version?
			assert (version >> 16) >= 0x8b43

			# Check for the two interesting bits
			assert 'eeMemory.bin' in fd.namelist()
			assert 'PCSX2 Internal Structures.dat' in fd.namelist()

			self._intdata = fd.read('PCSX2 Internal Structures.dat')

			self._readtag(strpad(b"BIOS", 32))
			self._discard(4 + 256) # Checksum + Desc
			self._readtag(strpad(b"cpuRegs", 32))
			self._mipsregs = self._parse_regs()
			self._eemem = fd.read('eeMemory.bin')

		# Attempt to recover the threads and their state
		# Hack taken from PCSX2 :)
		# Look for a particular set of insts in the BIOS
		offset = None
		for i in range(0, 0x10000, 4):
			i1, i2, i3 = struct.unpack("<III", self._eemem[i:i+12])
			if i1 == 0xac420000 and i2 == 0 and i3 == 0:
				# This is sw v0, 0(v0) + 2 nops
				off, opc = struct.unpack("<hH", self._eemem[i+24:i+28])
				offset = 0x20000 + off - 8
				print("Found TCB base at", hex(offset))
				break

		if offset:
			# Parse the 256 TCB entires for valid threads
			for i in range(256):
				addr = offset + i*19*4
				_, _, status, pc, sp, gp, pr, ipr, wt, _, wc, _, _, ipc = struct.unpack(
					"<IIIIIIHHIIIIII", self._eemem[addr:addr+52])
				# Pick only sleeping/waiting threads
				if status != 0:  # and status != 1:
					print("Found thread", status, hex(pc), hex(sp), hex(gp))


	def _readtag(self, data):
		if self._intdata[self._off:self._off + len(data)] != data:
			print("Data mismatch", self._off, data, self._intdata[self._off:self._off + len(data)])
			sys.exit(1)
		self._off += len(data)

	def _discard(self, length):
		self._off += length

	def _parse_regs(self):
		regs = {"gpr": [], "cp0": [], "sa": 0, "hi": 0, "lo": 0, "pc": 0}
		for i in range(32):
			reglo, reghi = struct.unpack("<QQ", self._intdata[self._off:self._off + 16])
			regs["gpr"].append(reglo)
			self._off += 16

		reglo, reghi = struct.unpack("<QQ", self._intdata[self._off:self._off + 16])
		regs["hi"] = reglo
		self._off += 16
		reglo, reghi = struct.unpack("<QQ", self._intdata[self._off:self._off + 16])
		regs["lo"] = reglo
		self._off += 16

		# Skip CP0 regs
		for i in range(32):
			regs["cp0"].append(struct.unpack("<I", self._intdata[self._off:self._off + 4])[0])
			self._off += 4

		regs["sa"] = struct.unpack("<I", self._intdata[self._off:self._off + 4])[0]
		self._off += 8
		regs["pc"] = struct.unpack("<I", self._intdata[self._off:self._off + 4])[0]
		self._off += 4

		return regs


rdr = StateReader(sys.argv[1])
rdr.parse()

# Pack registers using the Linux order
regdata  = b"".join(struct.pack("<Q", x) for x in rdr._mipsregs["gpr"])
regdata += struct.pack("<Q", rdr._mipsregs["lo"])
regdata += struct.pack("<Q", rdr._mipsregs["hi"])
regdata += struct.pack("<Q", rdr._mipsregs["pc"])
regdata += struct.pack("<Q", rdr._mipsregs["cp0"][8])  # bad vaddr
regdata += struct.pack("<Q", rdr._mipsregs["cp0"][12])
regdata += struct.pack("<Q", rdr._mipsregs["cp0"][13])
while len(regdata) < 364:
	regdata += b"\0"

oelf = ElfFile(e_type=ET_CORE, e_machine=EM_MIPS, e_flags=0x20920021)
oelf.add_note_block(regdata)
oelf.add_mem_block(0x0,      0x0,      7, rdr._eemem[:0x100000])   # Bios
oelf.add_mem_block(0x100000, 0x100000, 7, rdr._eemem[0x100000:])   # User RAM

with open(sys.argv[2], "wb") as fd:
	fd.write(oelf.serialize())


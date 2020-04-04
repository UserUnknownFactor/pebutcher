#!/usr/bin/python
# -*- coding: utf-8 -*-
"""pebutcher, Portable Executable section and imports modification

Add a new section to the PE file:
     from pebutcher import PE

     pe = PE("test.exe")
     section_data = b"sectionData"
     pe.add_section(".sect", 0x60000020, data=section_data)

Set section data:
     from pebutcher import PE

     pe = PE("test.exe")
     section_data = b"sectionData"
     section = pe.sections[-1]
     section.set_data(section_data)

Add a new entries to the import table:
     from pebutcher import PE

     pe = PE("test.exe")
     pe.add_new_imports({"USER32.dll": ["MessageBoxA"]})
"""
from pefile import *
from functools import wraps

NEW_IMP_SECTION = ".itt"
PAD_CHAR = b'\x90'
ZERO_CHAR = b'\x00'

def add_method(class_n):
     def decorator(func):
          @wraps(func)
          def wrapper(*args, **kwargs):
               return func(*args, **kwargs)

          setattr(class_n, func.__name__, wrapper)
          return func
     return decorator

@add_method(Structure)
def __setattr__(self, name, val):
     self.__dict__[name] = val
     if "__keys__" in self.__dict__:
          for item in self.__keys__:
               if name in item:
                    try:
                         new_data = self.__pack__()
                         self.pe.__data__ = (self.pe.__data__[:self.get_file_offset()] +
                                             new_data +
                                             self.pe.__data__[self.get_file_offset()+len(new_data):])
                    except AttributeError:
                         pass
                    break

def decorated_setattr(original):
     @wraps(original)
     def new_struct_setattr(*args, **kwargs):
          #print(args, kwargs)
          original(*args, **kwargs)
          Structure.__setattr__(args[0], args[1], args[2])
     return new_struct_setattr

SectionStructure.__setattr__ = decorated_setattr(SectionStructure.__setattr__)

@add_method(SectionStructure)
def set_data(self, data):
     self.set_raw_data_size(len(data))
     self.pe.__data__ = (self.pe.__data__[:self.PointerToRawData] +
                         data +
                         self.pe.__data__[self.PointerToRawData+len(data):])

     # Get the section index
     section_index = None
     for index, section in enumerate(self.pe.sections):
          if section.VirtualAddress == self.VirtualAddress:
               section_index = index
               break
     if not section_index:
          raise Exception("Unable to find the right section")

     section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() +
                             self.pe.FILE_HEADER.SizeOfOptionalHeader)
     section_offset = section_table_offset + section_index*0x28

     #self.pe.set_dword_at_offset(section_offset+0x08, len(data))
     self.Misc_VirtualSize = len(data)
     self.pe.adjust_optional_header()
     #self.pe.update()

@add_method(SectionStructure)
def set_raw_data_size(self, size):
     """ size should be a multiple of FileAlignment
     """
     FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
     if size % FileAlignment != 0:
          size = size - size % FileAlignment + FileAlignment

     old_section_size = self.SizeOfRawData
     new_section_size = size

     max_size = self.get_max_raw_data_size()

     if max_size and new_section_size > max_size:
          raise PEFormatError("Impossible to increase size")

     if old_section_size >= new_section_size:
          # nothing to do if the new size is smaller than the old one
          return

     # Padding the data to match a multiple of the FileAlignment
     data = ZERO_CHAR * (new_section_size - old_section_size)
     self.pe.__data__ = (self.pe.__data__[:self.PointerToRawData + self.SizeOfRawData] +
                         data +
                         self.pe.__data__[self.PointerToRawData + self.SizeOfRawData:])

     # Get the section index
     section_index = None
     for index, section in enumerate(self.pe.sections):
          if section.VirtualAddress == self.VirtualAddress:
               section_index = index
               break

     if not section_index:
          raise Exception("Unable to find the right section")

     section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() +
                             self.pe.FILE_HEADER.SizeOfOptionalHeader)
     section_offset = section_table_offset + section_index*0x28

     # Rewrite SizeOfRawData
     self.SizeOfRawData = new_section_size

     #print(hex(self.PointerToRawData))
     for index, section in enumerate(self.pe.sections):
          #print("> %s" % hex(section.PointerToRawData))
          if section.PointerToRawData > self.PointerToRawData:
               # Increment the value of the pointer to raw data of the next sections
               #print("increment %d" % index)
               section.PointerToRawData += len(data)

     #self.pe.update()

@add_method(SectionStructure)
def get_max_raw_data_size(self):
     next_section = None
     for section in self.pe.sections:
          if section.VirtualAddress > self.VirtualAddress:
               if not next_section:
                    next_section = section
                    continue

               if section.VirtualAddress < next_section.VirtualAddress:
                    next_section = section
     if not next_section:
          return None
     else:
          return next_section.VirtualAddress - self.VirtualAddress

@add_method(PE)
def add_new_imports(self, entries):
     """ Adds a readable and writable section
     """

     section = self.add_section(NEW_IMP_SECTION, 0xC0000040)
     section_offset = section.VirtualAddress

     # First set offset of the different parts of the Import tables
     IAT_offset = section_offset
     IAT_size = 0
     for dll, funcs in entries.items():
          if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
               IAT_size += (len(funcs)+1)*0x4
          elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
               IAT_size += (len(funcs)+1)*0x8
          else:
               IAT_size += (len(funcs)+1)*0x4

     if IAT_size % 0x10 != 0:
          IT_offset = IAT_offset + IAT_size - IAT_size % 0x10 + 0x10
     else:
          IT_offset = IAT_offset + IAT_size

     IT_size = (len(self.DIRECTORY_ENTRY_IMPORT) + len(entries)+1)*0x14

     if IT_size % 0x10 != 0:
          ILT_offset = IT_offset + IT_size - IT_size % 0x10 + 0x10
     else:
          ILT_offset = IT_offset + IT_size

     ILT_size = IAT_size

     if ILT_size % 0x10 != 0:
          DATA_offset = ILT_offset + ILT_size - ILT_size % 0x10 + 0x10
     else:
          DATA_offset = ILT_offset + ILT_size

     # IAT entry
     if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
          THUNK_DATA_STRUCT = self.__IMAGE_THUNK_DATA_format__
     elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
          THUNK_DATA_STRUCT = self.__IMAGE_THUNK_DATA64_format__
     else:
          THUNK_DATA_STRUCT = self.__IMAGE_THUNK_DATA_format__

     # Create byte arrays
     DATA = b''
     IAT_ILT = b''
     IT = b''

     # First add old IT entries
     old_IT_offset = self.get_offset_from_rva(self.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
     while self.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size > len(IT):
          IT_entry = Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__)
          IT_entry_data = self.__data__[old_IT_offset:old_IT_offset+IT_entry.sizeof()]
          IT_entry.__unpack__(IT_entry_data)

          if IT_entry.all_zeroes():
               break
          else:
               old_IT_offset += IT_entry.sizeof()
               IT += IT_entry_data


     # Then add new ones
     for dll, funcs in entries.items():
          IT_entry = Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__)
          IT_entry.OriginalFirstThunk = ILT_offset + len(IAT_ILT)
          IT_entry.TimeDateStamp = 0
          IT_entry.ForwarderChain = 0
          IT_entry.FirstThunk = IAT_offset + len(IAT_ILT)

          for func in funcs:
               DATA_entry = b'\x00\x00' # Hint
               DATA_entry += func.encode()
               if len(func) % 2 == 1:
                    DATA_entry += ZERO_CHAR
               else:
                    DATA_entry += b'\x00\x00'

               # IAT entry
               IAT_entry = Structure(THUNK_DATA_STRUCT)
               IAT_entry.ForwarderString = DATA_offset + len(DATA)

               DATA += DATA_entry
               IAT_ILT += IAT_entry.__pack__()

          # Add an empty IAT_ILT entry at the end
          IAT_entry = Structure(THUNK_DATA_STRUCT)
          IAT_entry.ForwarderString = 0

          IAT_ILT += IAT_entry.__pack__()

          IT_entry.Name = DATA_offset + len(DATA)
          DATA += dll.encode()
          if len(dll) % 2 == 1:
               DATA += ZERO_CHAR
          else:
               DATA += b'\x00\x00'

          IT += IT_entry.__pack__()

     IT_entry = Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__)
     IT_entry.OriginalFirstThunk = 0
     IT_entry.TimeDateStamp = 0
     IT_entry.ForwarderChain = 0
     IT_entry.FirstThunk = 0
     IT_entry.Name = 0
     IT += IT_entry.__pack__()

     # Write in binary!
     section_data = b''
     section_data += IAT_ILT
     section_data += ZERO_CHAR*(IT_offset-IAT_offset-len(IAT_ILT))
     section_data += IT
     section_data += ZERO_CHAR*(ILT_offset-IT_offset-len(IT))
     section_data += IAT_ILT
     section_data += ZERO_CHAR*(DATA_offset-ILT_offset-len(IAT_ILT))
     section_data += DATA
     section.set_data(section_data)

     self.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = IT_offset
     self.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = len(IT)
     # update entries
     self.DIRECTORY_ENTRY_IMPORT = self.parse_import_directory(IT_offset, len(IT))
     return section

@add_method(PE)
def get_import_address(self, dll_name, function):
     import_descs = self.DIRECTORY_ENTRY_IMPORT
     for imp_dll in import_descs:
          if imp_dll.dll.decode().lower() != dll_name.lower():
               continue
          for symbol in imp_dll.imports:
               if symbol.name.decode() == function:
                    return self.get_rva_from_offset(symbol.struct_iat.get_file_offset())

@add_method(PE)
def add_section(self, name, characteristics, data=None):
     """creates a new section with a size of fileAlignement
     """
     if type(name) == str:
          name = name.encode()
     if data != None and type(data) == str:
          data = data.encode()

     if self.FILE_HEADER.NumberOfSections == len(self.sections):

          FileAlignment = self.OPTIONAL_HEADER.FileAlignment
          SectionAlignment = self.OPTIONAL_HEADER.SectionAlignment

          if not data:
               VirtualSize = 0
               data = ZERO_CHAR*FileAlignment
          else:
               VirtualSize = len(data)
               data += ZERO_CHAR*(FileAlignment-len(data)%FileAlignment)

          if len(name) > 8:
               raise Exception("Error : Name is too long for a section")

          # Define Virtual Address (address of last byte of the last section + 1)
          if(self.sections[-1].Misc_VirtualSize == 0):
               VirtualAddress = self.sections[-1].VirtualAddress + SectionAlignment
          else:
               VirtualAddress = self.sections[-1].VirtualAddress + self.sections[-1].Misc_VirtualSize
          if (self.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
               VirtualAddress = (self.sections[-1].VirtualAddress + self.sections[-1].Misc_VirtualSize -
                                 (self.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)

          # Define Raw size
          RawSize = len(data)
          # Define Raw address
          RawAddress = self.sections[-1].PointerToRawData + self.sections[-1].SizeOfRawData
          # Add the new section
          self.__data__ = self.__data__[:RawAddress] + data + self.__data__[RawAddress:]
          # Patch the header
          self.__addSectionHeader(name, VirtualSize, VirtualAddress, RawSize, RawAddress, characteristics)
          self.adjust_optional_header()

     else:
          raise Exception("Error in PE File : invalid number of sections")
     #self.update()
     return self.sections[-1]

@add_method(PE)
def __addSectionHeader(self, name, VirtualSize, VirtualAddress, RawSize, RawAddress, characteristics):

     file_header_offset = self.DOS_HEADER.e_lfanew + 4
     section_table_offset = (file_header_offset + self.FILE_HEADER.sizeof() + self.FILE_HEADER.SizeOfOptionalHeader)
     new_section_offset = section_table_offset + self.FILE_HEADER.NumberOfSections*0x28

     # Check if we could place the new header between the last section header
     # and the first section
     if new_section_offset + 0x28 < self.OPTIONAL_HEADER.SizeOfHeaders:
          # Manually writing the data of the section header to the file.
          self.set_bytes_at_offset(new_section_offset, name)
          self.set_dword_at_offset(new_section_offset+0x08, VirtualSize)
          self.set_dword_at_offset(new_section_offset+0x0C, VirtualAddress)
          self.set_dword_at_offset(new_section_offset+0x10, RawSize)
          self.set_dword_at_offset(new_section_offset+0x14, RawAddress)
          self.set_dword_at_offset(new_section_offset+0x18, 0x0)
          self.set_dword_at_offset(new_section_offset+0x1C, 0x0)
          self.set_word_at_offset(new_section_offset+0x20, 0x0)
          self.set_word_at_offset(new_section_offset+0x22, 0x0)
          self.set_dword_at_offset(new_section_offset+0x24, characteristics)

          # Increase the number of sections
          self.FILE_HEADER.NumberOfSections += 1

          # Parse the section table of the file again and add the new section
          section = SectionStructure( self.__IMAGE_SECTION_HEADER_format__, pe=self )
          section.set_file_offset(new_section_offset)
          section_data = self.__data__[new_section_offset : new_section_offset + section.sizeof()]
          section.__unpack__(section_data)

          section.next_section_virtual_address = None
          self.sections[-1].next_section_virtual_address = VirtualAddress

          self.__structures__.append(section)

          section_flags = retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')

          # Set the section's flags according to section.Characteristics
          set_flags(section, section.Characteristics, section_flags)

          self.sections.append(section)
     else:
          raise NotImplementedError("Increase SizeOfheaders size")

@add_method(PE)
def adjust_optional_header(self):
     """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
          SizeOfUninitializedData of the optional header.
     """
     # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
     self.OPTIONAL_HEADER.SizeOfImage = (self.sections[-1].VirtualAddress +
                                             self.sections[-1].Misc_VirtualSize)

     self.OPTIONAL_HEADER.SizeOfCode = 0
     self.OPTIONAL_HEADER.SizeOfInitializedData = 0
     self.OPTIONAL_HEADER.SizeOfUninitializedData = 0

     # Recalculating the sizes by iterating over every section and checking if
     # the appropriate characteristics are set.
     for section in self.sections:
          if section.Characteristics & 0x00000020:
               # Section contains code.
               self.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
          if section.Characteristics & 0x00000040:
               # Section contains initialized data.
               self.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
          if section.Characteristics & 0x00000080:
               # Section contains uninitialized data.
               self.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

if __name__ == '__main__':
     import os
     pe = PE("test.exe")
     payload_length = 300
     imp_num = 2
     import_dir_length = len(pe.DIRECTORY_ENTRY_IMPORT)
     section_data = ZERO_CHAR * (5 + imp_num * 6 + payload_length)

     new_imp_sect = pe.add_new_imports({"msvcr120.dll": ["setlocale", "free", "calloc"],
                         "Kernel32.dll":["SetThreadLocale"]})

     # create new section data containing jump to OEP and calltable
                                        # read | execute | code
     new_sect = pe.add_section(".fix", 0x40000000 | 0x20000000 | 0x20, data=section_data)

     # gen jmp to OEP
     new_sect_addr = new_sect.VirtualAddress
     new_imp_sect_addr = new_imp_sect.VirtualAddress
     print('EP 0x%08x' % pe.OPTIONAL_HEADER.AddressOfEntryPoint)
     reljmp = pe.OPTIONAL_HEADER.AddressOfEntryPoint - (new_sect_addr + 5)
     print('JMP $-0x%08x' % abs(reljmp))
     print('New sectiion: 0x%08x' % new_sect_addr)
     new_section_data = bytearray(len(section_data))
     new_section_data[0:4] = b'\xE9' + reljmp.to_bytes(4, byteorder='little', signed=True)
     i = 5
     # gen calltable of added functions
     for dir_index in range(import_dir_length, len(pe.DIRECTORY_ENTRY_IMPORT)):
          item = pe.DIRECTORY_ENTRY_IMPORT[dir_index]
          print("  imports from:", str(item.dll, encoding='latin1'))
          for imp in item.imports:
               imp_address = imp.address
               new_section_data[i:i+1] = b'\xFF\x15'
               call_address = (new_sect_addr + 5 + i + 1) - imp_address # this is incorrect but IDK how to do it here
               print('    %s adress: 0x%08x; call: 0x%08x; thunk_rva: 0x%08x' % (imp.name.decode() , imp.address & 0xffffffff, call_address & 0xffffffff, imp.thunk_rva))
               new_section_data[i+2:i+5] = call_address.to_bytes(4, byteorder='little', signed=True)
               i += 6

     #new_section_data[i:len(new_section_data)-1] = PAD_CHAR * (len(new_section_data)-1 - i)
     new_sect.set_data(new_section_data)
     pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_sect_addr
     #pe.print_info()

     pe.write("test1.exe")
     pe.close()

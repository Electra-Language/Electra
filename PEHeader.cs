    using System;
    using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace Electra
    {
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PEHeader {

        #region MZ header

        public UInt16 e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss,
                      e_sp, e_csum, e_ip, e_cs, e_lsarlc, e_ovno;

        public fixed UInt16 e_res[4];

        public UInt16 e_oemid, e_oeminfo;

        public fixed UInt16 e_res2[10];

        public UInt32 e_lfanew;

        #endregion

        #region DOS Stub
        public fixed Byte unknown[14],
                             msg[38],
                            unknown_0[5],
                            unknown_empty[7];


        #endregion

        #region PE Header
        public UInt32 signature;

        public Machine machine;
        public UInt16 numberOfSections;

        public UInt32 timeDateStamp, pointerToSymbolTable, numberOfSymbols;

        public UInt16 sizeOfOptionalHeader, characteristics;
        #endregion

        #region PE Optional Header

        public UInt16 magic;
        
        public Byte majorLinkerVersion,minorLinkerVersion;

        public UInt32 sizeOfCode, sizeOfInitializedData, sizeOfUninitializedData, adressOfEntryPoint,
            baseofCode, baseofData, imageBase, sectionAlignment, fileAlignment;

        public UInt16 majorOperatingSystemVersion, minorOperatingSystemVersion, majorImageVersion,
            minorImageVersion, majorSubsystemVersion, minorSubsystemVersion;

        public UInt32 win32VersionValue, sizeOfImage, sizeOfHeaders, checksum;

        public UInt16 subSystem, dllCharacteristics;

        public UInt32 sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve, sizeOfHeapCommit, loaderflags,
            numberOfRvaAndSizes;

        #endregion

        #region Data Directories
        public fixed UInt32 dir[32];
        #endregion

        #region PE Code Section
        /*
         * End Of The PEHeader RafStudios Doesnt Know if It is or not.
         */

        public fixed Byte name[8];

        public UInt32 virtualSize, virtualAddress, sizeOfRawData, pointerToRawData, pointerToRelocations,
            pointerToLinenumbers;

        public UInt16 numberOfRelocations, numberOfLinenumbers;

        public UInt32 characteristics_0;

        #endregion

        #region Table Import
        public fixed UInt64 importTableBytes[12];
        #endregion
    }

    public static class PEHeaderFactory {
        
        unsafe static public PEHeader newHdr(List<Byte> opcodes,List<Byte> importOpcodes, UInt32 endMemAdress, Int32 offset,Boolean gui=false){

            PEHeader hdr = default(PEHeader);

            List<Byte> mockOpcodes = new List<Byte>(opcodes);
            while (mockOpcodes.Count % 512 != 0)
                mockOpcodes.Add(0);

            UInt16 sections = (UInt16)((importOpcodes != null) ? 2 : 1);

            #region MZ Header

            hdr.e_magic = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("MZ"), 0);
            hdr.e_cblp = (UInt16)(opcodes.Count % 512);
            hdr.e_cp = (UInt16)(Math.Ceiling((Decimal)((Decimal)opcodes.Count / 512M)));
            const UInt16 mzHeaderSize=(UInt16)(64 / 16);
            hdr.e_cparhdr = mzHeaderSize;
            hdr.e_minalloc = 0x0010;
            hdr.e_maxalloc = UInt16.MaxValue;
            hdr.e_sp=0x0140;
            hdr.e_lsarlc = 0x0040;
            const Byte MZheader_ByteSize = 64, DOSStub_ByteSize = 64;
            hdr.e_lfanew=(UInt32)(MZheader_ByteSize+DOSStub_ByteSize);
            #endregion

            #region DOS Stub

            Marshal.Copy(new Byte[] { 0x0E, 0x1F, 0xBA, 0x0E, 0xB4, 9, 0xCD, 0x21, 0xB8, 1, 0x4C, 0xCD, 0x21 }, 0, new IntPtr(hdr.unknown), 14);
            const string msg = "Sorry, But Electra Cannot Be Run In DOS Mode";
            Marshal.Copy(msg.Select(x => (Byte)x).ToArray(), 0, new IntPtr(hdr.msg), msg.Length);
            Marshal.Copy(new Byte[]{0x2E,0x0D,0x0A,0x24},0, new IntPtr(hdr.unknown_0),5);

            #endregion

            #region PE Header

            hdr.signature = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("PE"), 0);
            hdr.machine = Machine.I386;
            hdr.numberOfSections = sections;
            hdr.timeDateStamp = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc))).TotalSeconds;
            hdr.sizeOfOptionalHeader = 0x00E0;
            hdr.characteristics = 0x010f;


            #endregion

            #region PE Optional Header

            hdr.magic = 0x010B; //IMAGE_NT_OPTIONAL_HDR32_MAGIC // We Dont know what this means.
            hdr.minorLinkerVersion = 0x49;
            hdr.sizeOfCode = (UInt32)mockOpcodes.Count;
            hdr.sizeOfInitializedData = (UInt32)(mockOpcodes.Count + (importOpcodes != null ? importOpcodes.Count : 0));
            const UInt32 allignment = 0x00001000,imgBase=0x00400000;
            hdr.adressOfEntryPoint = allignment;
            hdr.baseofCode = allignment;
            hdr.baseofData = allignment;
            hdr.imageBase = imgBase;
            hdr.sectionAlignment = allignment;
            hdr.fileAlignment = (UInt32)512;
            hdr.majorOperatingSystemVersion = (UInt16)1;
            hdr.minorOperatingSystemVersion = (UInt16)0x000A;
            hdr.majorSubsystemVersion = (UInt16)3;
            hdr.sizeOfImage = (allignment * sections) + allignment;
            hdr.sizeOfHeaders = (UInt32)(Marshal.SizeOf(typeof(PEHeader)));
            hdr.subSystem = (UInt16)((gui) ? 2 : 3); //IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI
            hdr.sizeOfStackCommit = allignment;
            hdr.sizeOfStackReserve = allignment;
            hdr.sizeOfHeapReserve = allignment * 16;
            hdr.numberOfRvaAndSizes = 16;

            //End Of Super Long PE Header



            #endregion

            #region PE code section

            Marshal.Copy(".elra".toCodeSectNameBytes(), 0, new IntPtr(hdr.name), 8);
            hdr.virtualSize = (UInt32)(opcodes.Count + offset);
            hdr.virtualAddress = allignment;
            hdr.sizeOfRawData = (UInt32)mockOpcodes.Count;
            hdr.pointerToRawData = 512;
            hdr.characteristics_0 = 0xE0000060;

            #endregion

            #region Import Set

            if (importOpcodes.Count!=null)
            {
                // endMemAddress=0x00401000 + opcodes.count
                // imgBase=0x0040000
                UInt32 addr = endMemAddress - imgBase;

            }

            #endregion
            return hdr;
        }

        /// <return>Always returns 8 bytes To The Console,Programming Language I dont know</return>
        static private Byte[] toCodeSectNameBytes (this String str)
        {
            const Byte maxLenth = 8;

            if (str.Length > maxLenth) throw new Exception("Sorry, The Name Is Too Long");
            else if (!str.StartsWith(".")) throw new Exception("Error: Invalid Name Detected");

            List<Byte> bytes = str.Select(x => (Byte)x).ToList();
            bytes.AddRange(new Byte[maxLenth - str.Length]);

            return bytes.ToArray();
        }
    }
}
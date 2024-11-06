#!/usr/bin/env python3

import binascii
import shutil
import argparse
import os, time, zlib

from struct import pack, unpack, calcsize

HEADER_FORMAT = '!7L4B32s'    ### (Big-endian, 7 ULONGS, 4 UCHARs, 32-byte string)
HEADER_SIZE = calcsize(HEADER_FORMAT)    ### Should be 64-bytes
HEADER_MAGIC = 0x27051956

imageType = [['INVALID', ''],
        ['Standalone', 'standalone'],
        ['Kernel', 'kernel'],
        ['RAMDisk', 'ramdisk'],
        ['Multi-File', 'multi'],
        ['Firmware', 'firmware'],
        ['Script', 'script'],
        ['Filesystem', 'filesystem'],
        ['Flat Device Tree Blob', 'flat_dt'],
        ['Kirkwood Boot', 'kwbimage'],
        ['Freescale IMXBoot', 'imximage'],
        ['Davinci UBL', 'ublimage'],
        ['OMAP Config Header', 'omapimage'],
        ['Davinci AIS', 'aisimage'],
        ['Kernel (any load address)', 'kernel_noload']]

compressType = [['uncompressed', 'none'],
        ['gzip compressed', 'gzip'],
        ['bzip2 compressed', 'bzip2'],
        ['lzma compressed', 'lzma'],
        ['lzo compressed', 'lzo']]

archType = [['INVALID', ''],
        ['Alpha', 'alpha'],
        ['ARM', 'arm'],
        ['Intel x86', 'x86'],
        ['IA64', 'ia64'],
        ['MIPS', 'mips'],
        ['MIPS64', 'mips64'],
        ['PowerPC', 'ppc'],
        ['IBM S390', 's390'],
        ['SuperH', 'sh'],
        ['Sparc', 'sparc'],
        ['Sparc64', 'sparc64'],
        ['M68k', 'm68k'],
        ['MicroBlaze', 'microblaze'],
        ['Nios-II', 'nios2'],
        ['Blackfin', 'blackfin'],
        ['AVR32', 'avr32'],
        ['ST200', 'st200'],
        ['NDS32', 'nds32'],
        ['OpenRISC 1000', 'or1k']]
osType = [['INVALID', ''],
        ['OpenBSD', 'openbsd'],
        ['NetBSD', 'netbsd'],
        ['FreeBSD', 'freebsd'],
        ['4.4BSD', '4_4bsd'],
        ['Linux', 'linux'],
        ['SVR4', 'svr4'],
        ['Esix', 'esix'],
        ['Solaris', 'solaris'],
        ['Irix', 'irix'],
        ['SCO', 'sco'],
        ['Dell', 'dell'],
        ['NCR', 'ncr'],
        ['LynxOS', 'lynxos'],
        ['VxWorks', 'vxworks'],
        ['pSOS', 'psos'],
        ['QNX', 'qnx'],
        ['U-Boot Firmware', 'u-boot'],
        ['RTEMS', 'rtems'],
        ['Unity OS', 'unity'],
        ['INTEGRITY', 'integrity'],
        ['OSE', 'ose']]
def fromTable(table, index):
    if index < len(table):
        string = table[index][0]
    else:
        string = "Unknown:" + str(index)
    return string

def parseHeader(fh, offset=0):
    ### Save current position and seek to start position
    startpos = fh.tell()
    fh.seek(offset)

    try:
        block = fh.read(HEADER_SIZE)
    except IOError:
        print("File read error")
        exit(1)

    ### Names of fields in the image header
    keys = ['magic', 'headerCrc', 'time', 'size', 'loadAddr', 'entryAddr',
            'dataCrc', 'osType', 'arch', 'imageType', 'compression', 'name']

    ### Unpack the header into a dictionary of (key,value) pairs
    values = unpack(HEADER_FORMAT, block)
    hd = dict(zip(keys, values))

    ### if Multi-file image, append file information
    if hd['imageType'] == 4:
        hd['files'] = getMultiFileLengths(fh, fh.tell())
    ### Restore saved file position
    fh.seek(startpos)
    return hd


def crc(fileName):
	prev = 0
	for eachLine in open(fileName,"rb"):
		prev = zlib.crc32(eachLine, prev)
	return "%X"%(prev & 0xFFFFFFFF)

def calculateHeaderCrc(hd):
    ### Re-pack the list into a binary string
    ### Must calclate header CRC with CRC field set to 0.
    header = pack(HEADER_FORMAT, hd['magic'], 0, hd['time'], hd['size'],
        hd['loadAddr'], hd['entryAddr'], hd['dataCrc'], hd['osType'],
        hd['arch'], hd['imageType'], hd['compression'], hd['name'])
    return (zlib.crc32(header) & 0xffffffff)

def dumpHeader(hd):
    ### Dump header information and verify CRCs
    if hd['magic'] != HEADER_MAGIC:
        print("Invalid magic number!  This is not a valid uImage file.")
        print("Magic: expected 0x%x, but found %#08x" % (HEADER_MAGIC, hd['magic']))
        return
    print("Image name:\t", end='')
    print(hd['name'].decode("ascii", errors="ignore"))
    print("Created:\t%s" % time.ctime(hd['time']))
    print("Image type:\t", end='')
    print(fromTable(archType, hd['arch']), end=' ')
    print(fromTable(osType, hd['osType']), end=' ')
    print(fromTable(imageType, hd['imageType']), end=' ')
    print("(%s)" % fromTable(compressType, hd['compression']))
    print("Data size:\t%u Bytes" % hd['size'])
    print("Load Address:\t%#08x" % hd['loadAddr'])
    print("Entry Point:\t%#08x" % hd['entryAddr'])


    print("Header CRC:\t%#08x ..." % hd['headerCrc'], end=' ')
    if hd['headerCrc'] == calculateHeaderCrc(hd):
        print("OK")
    else:
        print("Mismatch!  Calculated CRC: %#08x" % calculateHeaderCrc(hd))
        # print("Mismatch!  Calculated CRC: %#08x" % str(calculateHeaderCrc(hd)))
        # print(str(calculateHeaderCrc(hd)))
        print(calculateHeaderCrc(hd))

    print("Data CRC:\t%#08x" % hd['dataCrc']) ###,


    ###### Verify Data CRC
    ###print "%#08x" % crc32File(fh)

    if hd['imageType'] == 4:
        print("Contents:")
        for index, length in enumerate(hd['files']):
            print("   Image %u: %u bytes" % (index,length))
    return

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", required=True,
	                    help="U-Boot binary file")
	args = parser.parse_args()
	x2 = crc(args.file)
	print(x2)

	bolv = './B0_pre_uboot_p2_bolvana.bin'
	bolv_fixed = './B0_pre_uboot_p2_done.bin'
	sig = './B0_pre_uboot_p2_done2.bin'
	sig3 = './B0_pre_uboot_p2_done3.bin'
	sig4 = './B0_pre_uboot_p2_done4.bin'
	B_sig_hdr = './B_sig_hdr.bin'

	B_justsig_bol = './B_justsig_bol.bin'
	B_justsig_res = './B_justsig_done.bin'

	shutil.copyfile(bolv, bolv_fixed)
	shutil.copyfile(B_justsig_bol, B_justsig_res)

	f = open(bolv_fixed, 'rb+')
	f.seek(20)

	hex_bytes = binascii.unhexlify(bytearray(int(x2, 16).to_bytes(4, 'little')).hex())

	print(bytearray(int(x2, 16).to_bytes(4, 'little')).hex())

	f.write(hex_bytes)

	f.seek(0)
	f.seek(1028)
	f.write(hex_bytes)
	f.close()

	stage3_crc = crc(bolv_fixed)
	print(stage3_crc)

	f = open(bolv_fixed, 'rb+')
	f.seek(1024)

	stage3_hex_bytes = binascii.unhexlify(bytearray(int(stage3_crc, 16).to_bytes(4, 'little')).hex())

	print(stage3_hex_bytes)
	# print('big: ' + binascii.unhexlify(bytearray(int(stage3_crc, 16).to_bytes(4, 'big')).hex()))
	print('xxxxxx: ' + bytearray(int(stage3_crc, 16).to_bytes(4, 'little')).hex())
	f.write(stage3_hex_bytes)
	f.close()

	with open(sig, 'wb') as outFile:
		with open(bolv_fixed, 'rb') as com, open(args.file, 'rb') as fort13:
			shutil.copyfileobj(com, outFile)
			shutil.copyfileobj(fort13, outFile)

	sig_crc = crc(sig)
	print('sig_crc: ' + sig_crc)
	# print('sig_crc: ' + binascii.unhexlify(sig_crc))
	# print('sig_crc: ' + bytearray(int(sig_crc, 16)))
	print(binascii.unhexlify(bytearray(int(sig_crc, 16).to_bytes(4, 'big')).hex()))
	print('=============')

	f = open(B_justsig_res, 'rb+')
	f.seek(24)
	f.write(binascii.unhexlify(bytearray(int(sig_crc, 16).to_bytes(4, 'big')).hex()))
	# f.write(bytearray(sig_crc).hex())
	f.close()

	f = open(B_justsig_res, 'rb+')
	d = parseHeader(f)
	dumpHeader(d)
	print(hex(calculateHeaderCrc(d))[2:10])
	print(binascii.unhexlify(hex(calculateHeaderCrc(d))[2:10]))
	f.close()

	f = open(B_justsig_res, 'rb+')
	f.seek(4)
	f.write(binascii.unhexlify(hex(calculateHeaderCrc(d))[2:10]))
	f.close()

	with open(sig4, "wb") as outFile, open(sig, "rb") as file2:
		outFile.write(file2.read())
	with open(sig4, "ab") as outFile, open(B_sig_hdr, "rb") as file2:
		outFile.write(file2.read())
	with open(sig4, "ab") as outFile, open(B_justsig_res, "rb") as file2:
		outFile.write(file2.read())


	# with open(sig3, 'wb') as outFile:
	# 	with open(sig, 'rb') as com, open(B_sig_hdr, 'rb') as fort13:
	# 		shutil.copyfileobj(com, outFile)
	# 		shutil.copyfileobj(fort13, outFile)

	# with open(sig4, 'wb') as outFile:
	# 	with open(sig3, 'rb') as com, open(B_justsig_res, 'rb') as fort13:
	# 		shutil.copyfileobj(com, outFile)
	# 		shutil.copyfileobj(fort13, outFile)

	# with open(sig4, 'wb') as outFile:
	# 	with open(sig3, 'rb') as com, open(B_justsig_p3, 'rb') as fort13:
	# 		shutil.copyfileobj(com, outFile)
	# 		shutil.copyfileobj(fort13, outFile)

	os.remove(sig)
	# os.remove(sig3)
	os.remove(bolv_fixed)


if __name__ == "__main__":
	main()

#include "CRC32.h"
#include <stdio.h>
#include <conio.h>
#include <Windows.h>

#define EFI_GUID GUID

#pragma pack(1)
///
/// MBR Partition Entry
///
typedef struct {
	UINT8 BootIndicator;
	UINT8 StartHead;
	UINT8 StartSector;
	UINT8 StartTrack;
	UINT8 OSIndicator;
	UINT8 EndHead;
	UINT8 EndSector;
	UINT8 EndTrack;
	UINT32 StartingLBA;
	UINT32 SizeInLBA;
} MBR_PARTITION_RECORD;
///
/// MBR Partition Table
///
typedef struct {
	UINT8 BootStrapCode[440];
	UINT8 UniqueMbrSignature[4];
	UINT8 Unknown[2];
	MBR_PARTITION_RECORD Partition[4];
	UINT16 Signature;
} MASTER_BOOT_RECORD;

///
/// GPT Header
/// 
typedef struct {
	CHAR Signature[8];
	UINT32 Revision;
	UINT32 HeaderSize;
	UINT32 Crc32OfHeader;
	UINT32 Reserved1;
	UINT64 CurrentLBA;
	UINT64 BackupLBA;
	UINT64 FirstLBAAfterPartitionHeaders;
	UINT64 LastUseableLBA;
	EFI_GUID DiskGuid;
	UINT64 PartitionEntriesLBA;
	UINT32 NumPartitionEntries;
	UINT32 PartitionEntrySize;
	UINT32 Crc32OfPartitionEntries;
	BYTE Reserved2[420];

} EFI_GPT_HEADER;

///
/// GPT Partition Entry.
///
typedef struct {
	EFI_GUID PartitionTypeGUID;
	EFI_GUID UniquePartitionGUID;
	UINT64 StartingLBA;
	UINT64 EndingLBA;
	UINT64 Attributes;
	WCHAR PartitionName[36];
} EFI_PARTITION_ENTRY;
#pragma pack()

BOOL isProtectiveMbrValid(MASTER_BOOT_RECORD* mbr)
{
	if (mbr->Signature != 0xAA55) return FALSE;
	UINT numZeroPartitions = 0;
	UINT partitionIndex = 0;
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < sizeof(mbr->Partition[0]); ++j)
		{
			if (((BYTE*)&mbr->Partition[i])[j])
			{
				partitionIndex = i;
				break;
			}
			if (j == sizeof(mbr->Partition[0]) - 1)
				numZeroPartitions++;
		}
	}
	if (numZeroPartitions != 3)
		return FALSE;
	if (mbr->Partition[partitionIndex].OSIndicator != 0xEE ||
		mbr->Partition[partitionIndex].StartingLBA != 0x01)
		return FALSE;
	// Everything seems good
	return TRUE;
}

BOOL isGptHeaderValid(EFI_GPT_HEADER* hdr)
{
	// We will check the signature and CRC32
	if (memcmp(&hdr->Signature, "EFI PART", 8))
		return FALSE;
	UINT32 original_crc32 = hdr->Crc32OfHeader;
	hdr->Crc32OfHeader = 0;
	UINT32 computed_crc32 = compute_crc32(hdr, hdr->HeaderSize);
	hdr->Crc32OfHeader = original_crc32;
	return computed_crc32 == original_crc32;
}

VOID FixGptCrcs(EFI_GPT_HEADER* restrict hdr, EFI_PARTITION_ENTRY* restrict partition_entry_array)
{
	// First, we must fix the partition CRC because it will affect the header crc
	UINT32 crc32 = compute_crc32(partition_entry_array, hdr->NumPartitionEntries * hdr->PartitionEntrySize);
	hdr->Crc32OfPartitionEntries = crc32;

	// Now compute CRC for GPT header
	hdr->Crc32OfHeader = 0;
	crc32 = compute_crc32(hdr, hdr->HeaderSize);
	hdr->Crc32OfHeader = crc32;

	// This function won't fail except catastrophically so no need to return a bool or status code
}

BOOL ChangePartitionUniqueGUID(EFI_PARTITION_ENTRY* part_entry)
{
	EFI_GUID ZeroGuid = { 0 };
	if (!IsEqualGUID(&part_entry->PartitionTypeGUID, &ZeroGuid))
	{
		if (!SUCCEEDED(CoCreateGuid(&part_entry->UniquePartitionGUID)))
			return FALSE;
		else return TRUE;
	}
	return TRUE; // Succeed if no GUID is needed
}

BOOL ChangeGuids(EFI_GPT_HEADER* restrict hdr, EFI_PARTITION_ENTRY* restrict part_entry_array)
{
	if (!SUCCEEDED(CoCreateGuid(&hdr->DiskGuid)))
		return FALSE;
	for (BYTE* i = part_entry_array; i < (BYTE*)part_entry_array + (hdr->NumPartitionEntries * hdr->PartitionEntrySize); i += hdr->PartitionEntrySize)
	{
		EFI_PARTITION_ENTRY* part = (EFI_PARTITION_ENTRY*)i;
		if (!ChangePartitionUniqueGUID(part)) return FALSE;
	}
	return TRUE;
}

VOID ConstructBackupHeader(_In_ EFI_GPT_HEADER* main_hdr, _Out_ EFI_GPT_HEADER* backup_hdr)
{
	memcpy(&backup_hdr->Signature, "EFI PART", 8);
	backup_hdr->Revision = main_hdr->Revision;
	backup_hdr->HeaderSize = main_hdr->HeaderSize;
	backup_hdr->Reserved1 = 0;
	backup_hdr->CurrentLBA = main_hdr->BackupLBA;
	backup_hdr->BackupLBA = main_hdr->CurrentLBA;
	backup_hdr->FirstLBAAfterPartitionHeaders = main_hdr->FirstLBAAfterPartitionHeaders;
	backup_hdr->LastUseableLBA = main_hdr->LastUseableLBA;
	backup_hdr->DiskGuid = main_hdr->DiskGuid;
	// This might clobber implementation-specific data on some platforms but is guaranteed to produce a valid gpt backup header
	backup_hdr->PartitionEntriesLBA = main_hdr->LastUseableLBA + 1;
	backup_hdr->NumPartitionEntries = main_hdr->NumPartitionEntries;
	backup_hdr->PartitionEntrySize = main_hdr->PartitionEntrySize;
	backup_hdr->Crc32OfPartitionEntries = main_hdr->Crc32OfPartitionEntries;
	memset(backup_hdr->Reserved2, 0x00, sizeof(backup_hdr->Reserved2));
	// Header fully built, so compute crc
	backup_hdr->Crc32OfHeader = 0;
	DWORD crc32 = compute_crc32(backup_hdr, backup_hdr->HeaderSize);
	backup_hdr->Crc32OfHeader = crc32;
}

BOOL PatchPartitionGuids(HANDLE drive)
{
	return PatchPartitionGuidsEx(drive, 512);
}

BOOL PatchPartitionGuidsEx(HANDLE drive, int lb_size)
{
	LARGE_INTEGER fp;
	fp.QuadPart = 0;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		return -1;

	MASTER_BOOT_RECORD* mbr = calloc(1, lb_size);
	DWORD bytes_read = 0;
	ReadFile(drive, mbr, lb_size, &bytes_read, NULL);
	if (bytes_read != lb_size)
	{
		free(mbr);
		return FALSE;
	}
	if (!isProtectiveMbrValid(mbr))
	{
		free(mbr);
		return FALSE;
	}
	free(mbr);

	EFI_GPT_HEADER* gpt_header = calloc(1, lb_size);
	ReadFile(drive, gpt_header, lb_size, &bytes_read, NULL);
	if (bytes_read != lb_size)
	{
		free(gpt_header);
		return FALSE;
	}
	if (!isGptHeaderValid(gpt_header))
	{
		free(gpt_header);
		return FALSE;
	}

	int size_of_partition_headers = gpt_header->NumPartitionEntries * gpt_header->NumPartitionEntries;
	EFI_PARTITION_ENTRY* partition_entries = calloc(1, size_of_partition_headers);
	fp.QuadPart = gpt_header->PartitionEntriesLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries);
		return FALSE;
	}
	ReadFile(drive, partition_entries, size_of_partition_headers, &bytes_read, NULL);
	if (bytes_read != size_of_partition_headers)
	{
		free(gpt_header); free(partition_entries);
		return FALSE;
	}
	// Don't bother checking partition entries considering they come from a known valid GPT header

	ChangeGuids(gpt_header, partition_entries);
	FixGptCrcs(gpt_header, partition_entries);

	if (!isGptHeaderValid(gpt_header))
	{
		free(gpt_header); free(partition_entries);
		return FALSE;
	}

	// Now that we have a new header and partition entries, we need to fix the gpt header
	// The partition entries will be copied to the first non-useable LBA
	EFI_GPT_HEADER* new_backup_hdr = calloc(1, lb_size);
	fp.QuadPart = gpt_header->BackupLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}
	ReadFile(drive, new_backup_hdr, lb_size, &bytes_read, NULL);
	if (bytes_read != lb_size)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}

	ConstructBackupHeader(gpt_header, new_backup_hdr);

	int bytes_written = 0;
	// First write the gpt header which is always at LBA 1
	fp.QuadPart = 1 * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}
	WriteFile(drive, gpt_header, lb_size, &bytes_written, NULL);
	if (bytes_written != lb_size)
	{
		free(gpt_header);  free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}

	// Next write the partition entries
	fp.QuadPart = gpt_header->PartitionEntriesLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}
	WriteFile(drive, partition_entries, size_of_partition_headers, &bytes_written, NULL);
	if (bytes_written != size_of_partition_headers)
	{
		free(gpt_header);  free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}

	// Next, the backup header
	fp.QuadPart = gpt_header->BackupLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}
	WriteFile(drive, new_backup_hdr, lb_size, &bytes_written, NULL);
	if (bytes_written != lb_size)
	{
		free(gpt_header);  free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}

	// Finally, the backup partition entries
	fp.QuadPart = new_backup_hdr->PartitionEntriesLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries); free(new_backup_hdr);
		return FALSE;
	}
	WriteFile(drive, partition_entries, size_of_partition_headers, &bytes_written, NULL);

	free(gpt_header);  free(partition_entries); free(new_backup_hdr);
	return bytes_written == size_of_partition_headers;
}

// This formats a guid in microsoft mixed endian. The out buffer must be 39 bytes
char* const FormatGuid(char* const output, GUID guid)
{
	sprintf_s(output, 39, "{%.8lX-%.4hX-%.4hX-%.4hX-%.2hX%.2hX%.2hX%.2hX%.2hX%.2hX}", 
		guid.Data1, guid.Data2, guid.Data3, *(WORD*)guid.Data4, 
		guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return output;
}

BOOL ListPartitionGuids(HANDLE drive)
{
	return ListPartitionGuidsEx(drive, 512);
}

ListPartitionGuidsEx(HANDLE drive, DWORD lb_size)
{
	LARGE_INTEGER fp;
	fp.QuadPart = 0;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		return -1;

	MASTER_BOOT_RECORD* mbr = calloc(1, lb_size);
	DWORD bytes_read = 0;
	ReadFile(drive, mbr, lb_size, &bytes_read, NULL);
	if (bytes_read != lb_size)
	{
		free(mbr);
		return FALSE;
	}
	if (!isProtectiveMbrValid(mbr))
	{
		free(mbr);
		return FALSE;
	}
	free(mbr);

	EFI_GPT_HEADER* gpt_header = calloc(1, lb_size);
	ReadFile(drive, gpt_header, lb_size, &bytes_read, NULL);
	if (bytes_read != lb_size)
	{
		free(gpt_header);
		return FALSE;
	}
	if (!isGptHeaderValid(gpt_header))
	{
		free(gpt_header);
		return FALSE;
	}

	int size_of_partition_headers = gpt_header->NumPartitionEntries * gpt_header->NumPartitionEntries;
	EFI_PARTITION_ENTRY* partition_entries = calloc(1, size_of_partition_headers);
	fp.QuadPart = gpt_header->PartitionEntriesLBA * lb_size;
	if (SetFilePointerEx(drive, fp, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		free(gpt_header); free(partition_entries);
		return FALSE;
	}
	ReadFile(drive, partition_entries, size_of_partition_headers, &bytes_read, NULL);
	if (bytes_read != size_of_partition_headers)
	{
		free(gpt_header); free(partition_entries);
		return FALSE;
	}

	char guid_name_buffer[39];
	printf("GPT header GUID (mixed endian): %s\n\n", FormatGuid(guid_name_buffer, gpt_header->DiskGuid));

	for (BYTE* i = partition_entries; i < (BYTE*)partition_entries + size_of_partition_headers; i += gpt_header->PartitionEntrySize)
	{
		EFI_PARTITION_ENTRY* part_entry = (EFI_PARTITION_ENTRY*)i;
		// If the partition type GUID is 0, the partition entry is unused
		EFI_GUID ZeroGuid = { 0 };
		if (IsEqualGUID(&part_entry->PartitionTypeGUID, &ZeroGuid))
			continue;
		printf("Partition header name: %ls\n", part_entry->PartitionName);
		printf("Partition header GUID (mixed endian): %s\n\n", FormatGuid(guid_name_buffer, part_entry->UniquePartitionGUID));
	}
	free(gpt_header); free(partition_entries);
	return TRUE;
}

int main()
{
	printf("Enter PhysicalDrive number: ");
	int drive_num = 0;
	if (scanf_s("%d", &drive_num) <= 0)
	{
		printf("Failed to read parameter, aborting\n");
		return -1;
	}
	char dev_name[40];
	sprintf_s(dev_name, 40, "\\\\.\\PhysicalDrive%d", drive_num);
	HANDLE file = CreateFileA(dev_name, FILE_READ_ACCESS | FILE_WRITE_ACCESS, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
	{
		printf("Invalid handle, aborting\n");
		return -1;
	}
	if (!ListPartitionGuids(file))
	{
		printf("Failed to list partition GUIDs, aborting\n");
		return -1;
	}
	printf("Do you want to randomize drive and partition guids for %s ? (y/n): ", dev_name);
	char response[2];
	fseek(stdin, 0, SEEK_END);
	fgets(response, 2, stdin);
	if (tolower(response[0]) != 'y')
	{
		printf("Exiting...\n");
		return 0;
	}

	if (!PatchPartitionGuids(file))
	{
		printf("Failed\n");
		return -1;
	}

	printf("Successfully patched GUIDs, exiting...\n");
	return 0;
}
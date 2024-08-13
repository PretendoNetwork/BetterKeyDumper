#include <coreinit/filesystem.h>
#include <coreinit/dynload.h>
#include <coreinit/thread.h>
#include <coreinit/time.h>
#include <coreinit/memdefaultheap.h>
#include <coreinit/memorymap.h>

#include <whb/proc.h>
#include <whb/log.h>
#include <whb/log_console.h>

#include <mocha/mocha.h>

#include <cstdlib>
#include <cstring>
#include <cstdio>

typedef struct WUT_PACKED CRYPTO_KeyHandle
{
    uint8_t valid;
    uint8_t desc;
    int16_t index;
    uint32_t permissions;
    uint32_t unk;
    uint8_t unk_[4];
} CRYPTO_KeyHandle; // .crypto.bss:0402bb2c - total size 0x800 bytes
WUT_CHECK_SIZE(CRYPTO_KeyHandle, 0x10);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0x0, valid);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0x1, desc);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0x2, index);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0x4, permissions);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0x8, unk);
WUT_CHECK_OFFSET(CRYPTO_KeyHandle, 0xC, unk_);

typedef struct WUT_PACKED CRYPTO_KeyData
{
    uint8_t valid;
    uint8_t data[32];
    uint8_t pad;
    uint16_t next;
} CRYPTO_KeyData; // .crypto.bss:0402972c - total size 0x2400
WUT_CHECK_SIZE(CRYPTO_KeyData, 0x24);
WUT_CHECK_OFFSET(CRYPTO_KeyData, 0x00, valid);
WUT_CHECK_OFFSET(CRYPTO_KeyData, 0x01, data);
WUT_CHECK_OFFSET(CRYPTO_KeyData, 0x21, pad);
WUT_CHECK_OFFSET(CRYPTO_KeyData, 0x22, next);

/* Keys and handles location in IOSU */
#define CRYPTO_KEY_DATA    0x0402972C
#define CRYPTO_KEY_HANDLES 0x0402BB2C

typedef struct BOSSKeys
{
    uint8_t dataKey[0x10];
    uint8_t pushmoreKey[0x10];
    union {
        uint8_t hmacKey[0x40];
        struct {
            uint8_t hmacKey1[0x20]; /* First half of HMAC key */
            uint8_t hmacKey2[0x20]; /* Second half of HMAC key */
        };
    };
} BOSSKeys; // Layout of BOSS keys for storing them to boss_keys.bin
WUT_CHECK_SIZE(BOSSKeys, 0x60);
WUT_CHECK_OFFSET(BOSSKeys, 0x00, dataKey);
WUT_CHECK_OFFSET(BOSSKeys, 0x10, pushmoreKey);
WUT_CHECK_OFFSET(BOSSKeys, 0x20, hmacKey);
WUT_CHECK_OFFSET(BOSSKeys, 0x20, hmacKey1);
WUT_CHECK_OFFSET(BOSSKeys, 0x40, hmacKey2);

typedef struct IDBEKeys
{
    uint8_t iv[0x10];
    uint8_t key0[0x10];
    uint8_t key1[0x10];
    uint8_t key2[0x10];
    uint8_t key3[0x10];
} IDBEKeys; // Internal layout of IDBE keys inside nn_idbe.rpl
WUT_CHECK_SIZE(IDBEKeys, 0x50);
WUT_CHECK_OFFSET(IDBEKeys, 0x00, iv);
WUT_CHECK_OFFSET(IDBEKeys, 0x10, key0);
WUT_CHECK_OFFSET(IDBEKeys, 0x20, key1);
WUT_CHECK_OFFSET(IDBEKeys, 0x30, key2);
WUT_CHECK_OFFSET(IDBEKeys, 0x40, key3);

void Mocha_KernelReadMemory(uint32_t address, uint8_t *out_buffer, size_t size) {
    for (uint32_t i = 0; i < size; i += sizeof(uint32_t)) {
        Mocha_IOSUKernelRead32(address + i, reinterpret_cast<uint32_t *>(out_buffer + i));
    }
}

void printHex(const char *title, uint8_t *ptr, size_t len) {
    char *buf = reinterpret_cast<char *>(MEMAllocFromDefaultHeap(len * 2));
    for (size_t i = 0; i < len; i++) {
        std::snprintf(buf + i * 2, 3, "%02x", ptr[i]);
    }

    WHBLogPrintf("%s: %s", title, buf);

    MEMFreeToDefaultHeap(buf);
}

int
main(int argc, char **argv)
{
    WHBProcInit();
    WHBLogConsoleInit();

    CRYPTO_KeyData *cryptoKeyData = reinterpret_cast<CRYPTO_KeyData *>(MEMAllocFromDefaultHeap(0x2400));
    CRYPTO_KeyHandle *cryptoKeyHandles = reinterpret_cast<CRYPTO_KeyHandle *>(MEMAllocFromDefaultHeap(0x800));
    BOSSKeys *bossKeys = reinterpret_cast<BOSSKeys *>(MEMAllocFromDefaultHeap(0x60));
    IDBEKeys *idbeKeys = reinterpret_cast<IDBEKeys *>(MEMAllocFromDefaultHeap(0x50));
    WiiUConsoleOTP *otp = reinterpret_cast<WiiUConsoleOTP *>(MEMAllocFromDefaultHeap(0x400));

    do {
        MochaUtilsStatus s = Mocha_InitLibrary();
        if (s != MOCHA_RESULT_SUCCESS) {
            WHBLogPrintf("Mocha_InitLibrary failed with error %d", s);
            break;
        }

        /* Read IOSU crypto data and handles to extract the BOSS keys */
        Mocha_KernelReadMemory(CRYPTO_KEY_DATA, reinterpret_cast<uint8_t *>(cryptoKeyData), 0x2400);
        Mocha_KernelReadMemory(CRYPTO_KEY_HANDLES, reinterpret_cast<uint8_t *>(cryptoKeyHandles), 0x800);

        std::memcpy(bossKeys->dataKey, cryptoKeyData[cryptoKeyHandles[0x1F].index].data, 0x10);
        std::memcpy(bossKeys->pushmoreKey, cryptoKeyData[cryptoKeyHandles[0x27].index].data, 0x10);
        std::memcpy(bossKeys->hmacKey1, cryptoKeyData[cryptoKeyHandles[0x20].index].data, 0x20);
        std::memcpy(bossKeys->hmacKey2, cryptoKeyData[cryptoKeyHandles[0x20].index + 1].data, 0x20);

        WHBLogPrintf("BOSS Data Key: %016s", bossKeys->dataKey);
        WHBLogPrintf("BOSS HMAC Key: %064s", bossKeys->hmacKey);
        printHex("BOSS Pushmore Key", bossKeys->pushmoreKey, 0x10);

        /* Load "nn_idbe.rpl", then get the relocated address of the keys from the instructions that load the pointer to the keys and IVs */
        OSDynLoad_Module idbeRpl;
        uint32_t idbePtr;
        OSDynLoad_Error dynLoadError = OSDynLoad_Acquire("nn_idbe.rpl", &idbeRpl);
        if (dynLoadError != OS_DYNLOAD_OK) {
            WHBLogPrintf("OSDynLoad_Acquire failed with error: %d", dynLoadError);
            break;
        }

        dynLoadError = OSDynLoad_FindExport(idbeRpl, OS_DYNLOAD_EXPORT_FUNC, "DestroyDownloadContext__Q2_2nn4idbeFPQ3_2nn4idbe15DownloadContext", reinterpret_cast<void **>(&idbePtr));
        if (dynLoadError != OS_DYNLOAD_OK) {
            WHBLogPrintf("OSDynLoad_FindExport failed with error: %d", dynLoadError);
            break;
        }

        uint32_t *lookupData = reinterpret_cast<uint32_t *>(idbePtr - 0x39C + 0x934); /* 0x0200039C - 0x39C + 0x934 */
        uint32_t idbeKeysPtr = ((lookupData[0] & 0xFFFF) << 16) | (lookupData[5] & 0xFFFF);
        std::memcpy(idbeKeys, reinterpret_cast<uint8_t *>(idbeKeysPtr), 0x50);

        /* Add spacing for IDBE */
        WHBLogPrintf("");

        /* Log the IDBE keys */
        printHex("IDBE IV", idbeKeys->iv, 0x10);
        printHex("IDBE Key 0", idbeKeys->key0, 0x10);
        printHex("IDBE Key 1", idbeKeys->key1, 0x10);
        printHex("IDBE Key 2", idbeKeys->key2, 0x10);
        printHex("IDBE Key 3", idbeKeys->key3, 0x10);

        OSDynLoad_Release(idbeRpl);

        /* Read OTP data */
        Mocha_ReadOTP(otp);

        Mocha_DeInitLibrary();
    } while(0);

    while(WHBProcIsRunning()) {
        WHBLogConsoleDraw();
        OSSleepTicks(OSMillisecondsToTicks(100));
    }

    /* Initialize FS for saving the keys on exit. Using the wut devoptab seems to break the IDBE keys */
    FSInit();

    FSMountSource outSdPath;
    char mountPath[128];
    FSClient *fsClient = reinterpret_cast<FSClient *>(MEMAllocFromDefaultHeap(sizeof(FSClient)));
    FSCmdBlock *fsCmdBlock = reinterpret_cast<FSCmdBlock *>(MEMAllocFromDefaultHeap(sizeof(FSCmdBlock)));

    FSAddClient(fsClient, FS_ERROR_FLAG_ALL);
    FSInitCmdBlock(fsCmdBlock);

    /* Mount the SD Card */
    FSGetMountSource(fsClient, fsCmdBlock, FS_MOUNT_SOURCE_SD, &outSdPath, FS_ERROR_FLAG_ALL);
    FSMount(fsClient, fsCmdBlock, &outSdPath, mountPath, 128, FS_ERROR_FLAG_ALL);

    FSFileHandle otpFile = -1;
    FSFileHandle bossFile = -1;
    FSFileHandle idbeFile = -1;

    /* Save OTP data to "sd:/otp.bin" */
    FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/otp.bin", "wb", &otpFile, FS_ERROR_FLAG_ALL);
    FSWriteFile(fsClient, fsCmdBlock, reinterpret_cast<uint8_t *>(otp), sizeof(WiiUConsoleOTP), 1, otpFile, 0, FS_ERROR_FLAG_ALL);
    FSCloseFile(fsClient, fsCmdBlock, otpFile, FS_ERROR_FLAG_ALL);

    /* Save BOSS keys to "sd:/boss_keys.bin" */
    FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/boss_keys.bin", "wb", &bossFile, FS_ERROR_FLAG_ALL);
    FSWriteFile(fsClient, fsCmdBlock, reinterpret_cast<uint8_t *>(bossKeys), sizeof(BOSSKeys), 1, bossFile, 0, FS_ERROR_FLAG_ALL);
    FSCloseFile(fsClient, fsCmdBlock, bossFile, FS_ERROR_FLAG_ALL);

    /* Save IDBE keys to "sd:/idbe_keys.bin" */
    FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/idbe_keys.bin", "wb", &idbeFile, FS_ERROR_FLAG_ALL);
    FSWriteFile(fsClient, fsCmdBlock, reinterpret_cast<uint8_t *>(idbeKeys), sizeof(IDBEKeys), 1, idbeFile, 0, FS_ERROR_FLAG_ALL);
    FSCloseFile(fsClient, fsCmdBlock, idbeFile, FS_ERROR_FLAG_ALL);

    FSUnmount(fsClient, fsCmdBlock, mountPath, FS_ERROR_FLAG_ALL);
    FSDelClient(fsClient, FS_ERROR_FLAG_ALL);
    FSShutdown();

    MEMFreeToDefaultHeap(fsCmdBlock);
    MEMFreeToDefaultHeap(fsClient);

    MEMFreeToDefaultHeap(cryptoKeyData);
    MEMFreeToDefaultHeap(cryptoKeyHandles);
    MEMFreeToDefaultHeap(idbeKeys);
    MEMFreeToDefaultHeap(otp);

    WHBLogPrintf("Exiting... good bye.");
    WHBLogConsoleDraw();
    OSSleepTicks(OSMillisecondsToTicks(1000));

    WHBLogConsoleFree();
    WHBProcShutdown();
    return 0;
}

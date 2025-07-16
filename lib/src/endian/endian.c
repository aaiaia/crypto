#ifdef DEBUG
#include <stdio.h>
#define dprintf(...)    printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif /* DEBUG */

#include "endian/endian.h"

void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size)
{
#define _MEM_ALIGN_MSK_ 0x3UL   // Bytes
    if((size & _MEM_ALIGN_MSK_) == 0UL)
    {
        for(size_t i = 0UL; i < EDCSIZE2W32LEN(size); i++)
        {
            dst[i] = EDCVAL32(src[i]);
        }
    }
    else
    {
        // align error
    }
#undef _MEM_ALIGN_MSK_
}

void conv64bitEndian(uint64_t* dst, const uint64_t* src, const size_t size)
{
#define _MEM_ALIGN_MSK_ 0x7UL   // Bytes
    if((size & _MEM_ALIGN_MSK_) == 0UL)
    {
        for(size_t i = 0UL; i < EDCSIZE2W64LEN(size); i++)
        {
            dst[i] = EDCVAL64(src[i]);
        }
    }
    else
    {
        // align error
    }
#undef _MEM_ALIGN_MSK_
}

#ifdef DEBUG
void test_endian_environments(void)
{
    /* Endian Value Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        uint32_t ui32_symbol = 0x428a2f98u;
        uint8_t ui8_arr_4B[] = { 0x42u, 0x8au, 0x2fu, 0x98u };
        uint32_t ui32_endian = EDCVAL32(*((uint32_t*)ui8_arr_4B));

        dprintf("32bit symbol = 0x%08x\n", ui32_symbol);
        dprintf("4 Byte Array = 0x%02x%02x%02x%02x\n", 
                ui8_arr_4B[0], ui8_arr_4B[1], 
                ui8_arr_4B[2], ui8_arr_4B[3]
        );
        dprintf("4Byte->32bit = 0x%08x\n", *((uint32_t*)ui8_arr_4B));
        dprintf("4Byte->BigEd = 0x%08x\n", ui32_endian);
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Endian Index Convert Test */
    {
#define _TEST_SIZE_ 8U
        dprintf("--------------------------------------------------------------------------------\n");

        dprintf("MACRO EDCIDX32() TEST\n");
        for(size_t idx = 0UL; idx < _TEST_SIZE_; idx++)
        {
            dprintf("%2lu -> %2lu, ", idx, EDCIDX32(size_t, idx));
            if((idx != 0U) && ((idx&0x3U) == 0x03)) dprintf("\n");
        }
        dprintf("\n");

        dprintf("================================================================================\n");
#undef  _TEST_SIZE_
    }

    /* Endian Value Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        uint64_t ui64_symbol = 0x428a2f981234abcdu;
        uint8_t ui8_arr_8B[] = { 0x42u, 0x8au, 0x2fu, 0x98u, 0x12u, 0x34u, 0xabu, 0xcdu, };
        uint64_t ui64_endian = EDCVAL64(*((uint64_t*)ui8_arr_8B));

        dprintf("64bit symbol = 0x%016lx\n", ui64_symbol);
        dprintf("8 Byte Array = 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", 
                ui8_arr_8B[0], ui8_arr_8B[1], ui8_arr_8B[2], ui8_arr_8B[3], 
                ui8_arr_8B[4], ui8_arr_8B[5], ui8_arr_8B[6], ui8_arr_8B[7]
        );
        dprintf("8Byte->64bit = 0x%016lx\n", *((uint64_t*)ui8_arr_8B));
        dprintf("8Byte->BigEd = 0x%016lx\n", ui64_endian);
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Endian Index Convert Test */
    {
#define _TEST_SIZE_ 16U
        dprintf("--------------------------------------------------------------------------------\n");

        dprintf("MACRO EDCIDX64() TEST\n");
        for(size_t idx = 0UL; idx < _TEST_SIZE_; idx++)
        {
            dprintf("%2lu -> %2lu, ", idx, EDCIDX64(size_t, idx));
            if((idx != 0U) && ((idx&0x7U) == 0x07)) dprintf("\n");
        }
        dprintf("\n");

        dprintf("================================================================================\n");
#undef  _TEST_SIZE_
    }
}
#endif /* DEBUG */

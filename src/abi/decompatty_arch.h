#ifndef DECOMPATTY_ARCH_H
#define DECOMPATTY_ARCH_H

#define DECOMPATTY_ABI_VERSION 1u

#include <stdint.h>
#include <stddef.h>

typedef int32_t decompatty_status;

#define DECOMPATTY_OK 0
#define DECOMPATTY_ERR_INVAL (-1)
#define DECOMPATTY_ERR_UNSUPPORTED (-2)
#define DECOMPATTY_ERR_NOMEM (-3)
#define DECOMPATTY_ERR_INTERNAL (-4)

typedef uint32_t decompatty_format;

#define DECOMPATTY_FORMAT_MACHO (1u << 0)
#define DECOMPATTY_FORMAT_ELF (1u << 1)
#define DECOMPATTY_FORMAT_PE (1u << 2)

typedef uint32_t decompatty_cpu;

#define DECOMPATTY_CPU_UNKNOWN 0x00000000u
#define DECOMPATTY_CPU_X86_64 0x00000007u
#define DECOMPATTY_CPU_ARM64 0x0000000Cu
#define DECOMPATTY_CPU_PPC 0x00000012u
#define DECOMPATTY_CPU_RISCV 0x00000018u

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    void (*log)(void* context, const char* msg);
    void* log_context;
} decompatty_host;

typedef struct {
    const uint8_t* data;
    uint64_t length;
    uint64_t address;
    uint64_t file_offset;
    const char* section_name;
} decompatty_section;

typedef struct {
    uint64_t address;
    uint32_t section_offset;
    uint32_t mnemonic_offset;
    uint32_t operands_offset;
    uint8_t  length;
    uint8_t  flags;
} decompatty_instruction;

#define DECOMPATTY_INSTR_BRANCH 0x1u /* instruction is a branch target */

typedef struct decompatty_arch_api {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t cpu;
    uint32_t formats;
    uint8_t bitness;
    uint8_t endianness;
    const char* name;

    decompatty_status (*create)(const decompatty_host* host, void** out_context);
    void (*destroy)(void* context);
    decompatty_status (*disassemble)(void* context, const decompatty_section* section, const decompatty_host* host);
    size_t (*instruction_count)(const void* context);
    const decompatty_instruction* (*instruction_at)(const void* context, size_t index);
    const char* (*string_at)(const void* context, uint32_t offset);
} decompatty_arch_api;

#if defined(__GNUC__) || defined(__clang__)
#define DECOMPATTY_ABI_EXPORT __attribute__((visibility("default")))
#else
#define DECOMPATTY_ABI_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

DECOMPATTY_ABI_EXPORT const decompatty_arch_api* decompatty_arch_api_v1(void);

#ifdef __cplusplus
}
#endif

#define DECOMPATTY_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#ifdef __cplusplus
#undef DECOMPATTY_STATIC_ASSERT
#define DECOMPATTY_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#endif

DECOMPATTY_STATIC_ASSERT(offsetof(decompatty_arch_api, cpu) == 8,
                         "struct_size and abi_version must stay first");
DECOMPATTY_STATIC_ASSERT(sizeof(void*) == 8, "64-bit hosts only");
DECOMPATTY_STATIC_ASSERT(sizeof(decompatty_cpu) == 4,
                         "must match cpu_type_t in format/binary_format.hpp");
DECOMPATTY_STATIC_ASSERT(sizeof(decompatty_status) == 4, "pinned to int32_t");

#endif /* DECOMPATTY_ARCH_H */
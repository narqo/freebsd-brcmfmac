#ifndef HACK_H
#define HACK_H

/*
 * Zig translate-c bitfield workaround.
 *
 * Zig's C translator demotes structs with bitfields to opaque types.
 * FreeBSD headers use bitfields in struct user_segment_descriptor and
 * struct gate_descriptor, which are embedded in struct pcpu.
 *
 * This header must be included before other system headers in @cImport.
 */

#include <sys/types.h>

#define user_segment_descriptor user_segment_descriptor_bitfields
#define gate_descriptor gate_descriptor_bitfields

#include <x86/segments.h>

#undef user_segment_descriptor
#undef gate_descriptor

struct user_segment_descriptor {
    uint64_t raw;
};

struct gate_descriptor {
    uint64_t raw[2];
};

#endif

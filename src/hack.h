#ifndef LOCAL_H
#define LOCAL_H

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

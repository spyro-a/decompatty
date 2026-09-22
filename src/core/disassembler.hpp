#pragma once

class dissassembler_t {
public:
    dissassembler_t() = default;
    virtual ~dissassembler_t() = 0;

    virtual void disassemble() = 0;
};
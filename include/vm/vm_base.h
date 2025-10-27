/**
 * @file vm_base.h
 * @brief File containing the base class for the virtual machine
 * @author Vishank Singh, https://VishankSingh
 */
#ifndef VM_BASE_H
#define VM_BASE_H


#include "registers.h"
#include "memory_controller.h"
#include "alu.h"

#include "vm_asm_mw.h"

#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

enum SyscallCode {
    SYSCALL_PRINT_INT = 1,
    SYSCALL_PRINT_FLOAT = 2,
    SYSCALL_PRINT_DOUBLE = 3,
    SYSCALL_PRINT_STRING = 4,
    SYSCALL_EXIT = 10,
    SYSCALL_READ = 63,
    SYSCALL_WRITE = 64,
};

struct IF_ID_REGISTER{
  uint32_t instruction;
  uint64_t pc;

  bool isEmpty;
  bool isFloat;
  bool isDouble;
};

struct ID_EX_REGISTER{
  uint64_t pc;
  uint64_t rs1_value;
  uint64_t rs2_value;
  uint64_t rs3_value;
  uint8_t rd;
  int32_t imm;
  
  bool alu_src;
  bool mem_to_reg;
  bool reg_write;
  bool mem_read;
  bool mem_write;
  bool branch;
  uint8_t alu_op;
  alu::AluOp alu_operation;

  uint8_t opcode;
  uint8_t funct3;
  uint8_t funct7;
  uint8_t rm;

  bool isEmpty;
  bool isFloat;
  bool isDouble;
};

struct EX_MEM_REGISTER{
  uint64_t alu_result;
  uint64_t rs2_value;
  uint8_t rd;
  uint64_t pc;
  int32_t imm;
  uint8_t fcsr_status;
  
  bool mem_to_reg;
  bool reg_write;
  bool mem_read;
  bool mem_write;
  bool branch;

  uint8_t opcode;
  uint8_t funct3;
  uint8_t funct7;

  bool isEmpty;
  bool isFloat;
  bool isDouble;
};

struct MEM_WB_REGISTER{
  uint64_t alu_result;
  uint64_t mem_result;
  uint8_t rd;
  int32_t imm;
  uint64_t pc;

  bool mem_to_reg;
  bool reg_write;

  uint8_t opcode;
  uint8_t funct3;
  uint8_t funct7;

  bool isEmpty;
};

class VmBase {
public:
    VmBase() = default;
    ~VmBase() = default;

    AssembledProgram program_;
    std::atomic<bool> stop_requested_ = false;
    std::mutex input_mutex_;
    std::condition_variable input_cv_;
    std::queue<std::string> input_queue_;

    std::vector<uint64_t> breakpoints_;

    uint32_t current_instruction_{};
    uint64_t program_counter_{};
    
    unsigned int cycle_s_{};
    unsigned int instructions_retired_{};
    float cpi_{};
    float ipc_{};
    unsigned int stall_cycles_{};
    unsigned int branch_mispredictions_{};

    std::string output_status_;

    
    // Declare the pipeline registers.
    static IF_ID_REGISTER IF_ID_REG;
    static ID_EX_REGISTER ID_EX_REG;
    static EX_MEM_REGISTER EX_MEM_REG;
    static MEM_WB_REGISTER MEM_WB_REG;


    MemoryController memory_controller_;
    RegisterFile registers_;
    
    alu::Alu alu_;


    void LoadProgram(const AssembledProgram &program);
    uint64_t program_size_ = 0;

    uint64_t GetProgramCounter() const;
    void UpdateProgramCounter(int64_t value);
    
    int32_t ImmGenerator(uint32_t instruction);

    void AddBreakpoint(uint64_t val, bool is_line = true);
    void RemoveBreakpoint(uint64_t val, bool is_line = true);
    bool CheckBreakpoint(uint64_t address);

    // void fetchInstruction();
    // void decodeInstruction();
    // void executeInstruction();
    // void memoryAccess();
    // void writeback();

    // void HandleSyscall();
    void PrintString(uint64_t address);

    virtual void Run() = 0;
    virtual void DebugRun() = 0;
    virtual void Step() = 0;
    virtual void Undo() = 0;
    virtual void Redo() = 0;
    virtual void Reset() = 0;
    void DumpState(const std::filesystem::path &filename);

    void ModifyRegister(const std::string &reg_name, uint64_t value);
    void PushInput(const std::string& input) {
        std::lock_guard<std::mutex> lock(input_mutex_);
        input_queue_.push(input);
        input_cv_.notify_one();
    }

};

#endif // VM_BASE_H

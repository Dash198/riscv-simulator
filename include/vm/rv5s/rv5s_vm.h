/**
 * @file rvss_vm.h
 * @brief RVSS VM definition
 * @author Vishank Singh, https://github.com/VishankSingh
 */
#ifndef RV5S_VM_H
#define RV5S_VM_H


#include "vm/vm_base.h"

#include "rv5s_control_unit.h"

#include <stack>
#include <vector>
#include <iostream>
#include <cstdint>

// TODO: use a circular buffer instead of a stack for undo/redo

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
  bool isFloat;
  bool isDouble;
};

class RV5SVM : public VmBase {
 public:
  RV5SControlUnit control_unit_;
  std::atomic<bool> stop_requested_ = false;

  // Declare the pipeline registers.
  static IF_ID_REGISTER IF_ID_REG;
  static ID_EX_REGISTER ID_EX_REG;
  static EX_MEM_REGISTER EX_MEM_REG;
  static MEM_WB_REGISTER MEM_WB_REG;

  std::stack<StepDelta> undo_stack_;
  std::stack<StepDelta> redo_stack_;
  // RingUndoRedo history_{1000}; // or however many steps you want to store

  StepDelta current_delta_;

  // intermediate variables
  int64_t execution_result_{};
  int64_t memory_result_{};
  // int64_t memory_address_{};
  // int64_t memory_data_{};
  uint64_t return_address_{};

  bool branch_flag_ = false;
  int64_t next_pc_{}; // for jal, jalr,

  // CSR intermediate variables
  uint16_t csr_target_address_{};
  uint64_t csr_old_value_{};
  uint64_t csr_write_val_{};
  uint8_t csr_uimm_{};

  void ExecuteCsr();
  void HandleSyscall();

  void WriteBackCsr();

  void IF();
  void ID();
  void IDFP();

  void EX();
  void EXF();
  void EXD();

  void MEM();
  void MEMF();
  void MEMD();

  void WB();
  void WBF();
  void WBD();

  RV5SVM();
  ~RV5SVM();

  void Run() override;
  void DebugRun() override;
  void Step() override;
  void Undo() override;
  void Redo() override;
  void Reset() override;

  void RequestStop() {
    stop_requested_ = true;
  }

  bool IsStopRequested() const {
    return stop_requested_;
  }
  
  void ClearStop() {
    stop_requested_ = false;
  }

  void PrintType() {
    std::cout << "RV5SVM" << std::endl;
  }
};

#endif // RVSS_VM_H

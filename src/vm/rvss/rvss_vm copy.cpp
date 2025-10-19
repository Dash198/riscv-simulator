/**
 * @file rvss_vm.cpp
 * @brief RVSS VM implementation
 * @author Vishank Singh, https://github.com/VishankSingh
 */

#include "vm/rvss/rvss_vm.h"

#include "utils.h"
#include "globals.h"
#include "common/instructions.h"
#include "config.h"

#include <cctype>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <tuple>
#include <stack>  
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <type_traits>

// Load the instruction set and instruction encoding.
using instruction_set::Instruction;
using instruction_set::get_instr_encoding;

// Call the base class constructor, write the initial
// register and VM states to a file.
RVSSVM::RVSSVM() : VmBase() {
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Initialise the desructor.
RVSSVM::~RVSSVM() = default;

// Fetch the current instruction (IF stage).
void RVSSVM::Fetch() {
  current_instruction_ = memory_controller_.ReadWord(program_counter_);
  UpdateProgramCounter(4);
}

// Execute the IF stage of the pipeline.
// Fetch the next insturction and send it with PC to the IF_ID register.
void RVSSM::IF(){
  IF_ID_REG.instruction = memory_controller_.ReadWord(program_counter_);
  IF_ID_REG.pc = program_counter_;
  UpdateProgramCounter(4);

}

// Decode the current instruction (ID stage).
void RVSSVM::Decode() {
  control_unit_.SetControlSignals(current_instruction_);
}

// Execute the ID stage for the pipeline.
// Find out the register valyes, the immediate and the required contorl signals.
// Store them in the ID_EX register.
void RVSSVM::ID(){
  // Pass on the PC to the next reg.
  ID_EX_REG.pc = ID_ID_REG.pc;
  
  // Find rs1 and rs2.
  uint64_t current_instruction = IF_ID_REG.instruction;
  uint8_t rs1 = (current_instruction >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction >> 20) & 0b11111;

  // Assign their values.
  ID_EX_REG.imm = ImmGenerator(current_instruction);
  ID_EX_REG.rs1_value = registers_.ReadGpr(rs1);
  ID_EX_REG.rs2_value = registers_.ReadGpr(rs2);

  // Find rd.
  ID_EX_REG.rd = (current_instruction >> 7) & 0b11111;

  // Set the control signals.
  control_unit_.SetControlSignals(current_instruction);
  ID_EX_REG.alu_src = control_unit_.GetAluSrc();
  ID_EX_REG.mem_to_reg = control_unit_.GetMemToReg();
  ID_EX_REG.reg_write = control_unit_.GetRegWrite();
  ID_EX_REG.mem_read = control_unit_.GetMemRead();
  ID_EX_REG.mem_write = control_unit_.GetMemWrite();
  ID_EX_REG.branch = control_unit_.GetBranch();
  ID_EX_REG.alu_op = control_unit_.GetAluOp();
  ID_EX_REG.alu_operation = control_unit_.GetAluSignal(current_instruction, control_unit_.GetAluOp();)

  // Forward the instruction information.
  ID_EX_REG.opcode = current_instruction & 0b1111111;
  ID_EX_REG.funct3 = (current_instruction >> 12) & 0b111;
  ID_EX_REG.funct7 = (current_instruction >> 25) & 0b1111111;
}

// Execute the current instruction (EX stage).
void RVSSVM::Execute() {
  // Get the opcode of the instruction.
  uint8_t opcode = current_instruction_ & 0b1111111;
  // Get the funct3 of the instruction.
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;

  // Syscall instruction.
  if (opcode == get_instr_encoding(Instruction::kecall).opcode && 
      funct3 == get_instr_encoding(Instruction::kecall).funct3) {
    HandleSyscall();
    return;
  }

  // Float instruction, hand over to float execution unit.
  if (instruction_set::isFInstruction(current_instruction_)) { // RV64 F
    ExecuteFloat();
    return;
  
  // Double instruction, hand over to respective unit.
  } else if (instruction_set::isDInstruction(current_instruction_)) {
    ExecuteDouble();
    return;
  // CSR.
  } else if (opcode==0b1110011) {
    ExecuteCsr();
    return;
  }

  // Find out rs1 and rs2.
  uint8_t rs1 = (current_instruction_ >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;

  // Find the immediate value.
  int32_t imm = ImmGenerator(current_instruction_);

  // Retrieve the values stored in rs1 and rs2.
  uint64_t reg1_value = registers_.ReadGpr(rs1);
  uint64_t reg2_value = registers_.ReadGpr(rs2);

  // Overflow check.
  bool overflow = false;

  // Check if the second operand comes from rs2 or the immediate.
  // If it is the immediate then replace reg2_value with the sign-extended immediate value.
  if (control_unit_.GetAluSrc()) {
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  // Find the operation to execute.
  alu::AluOp aluOperation = control_unit_.GetAluSignal(current_instruction_, control_unit_.GetAluOp());
  // Perform the computation and check for overflow.
  std::tie(execution_result_, overflow) = alu_.execute(aluOperation, reg1_value, reg2_value);

  // If the instruction is a branch type instruction.
  if (control_unit_.GetBranch()) {
    // Check if the opcode was for jal or jalr.
    if (opcode==get_instr_encoding(Instruction::kjalr).opcode || 
        opcode==get_instr_encoding(Instruction::kjal).opcode) {
      
      // Store the return point.
      next_pc_ = static_cast<int64_t>(program_counter_); // PC was already updated in Fetch()
      // Go back to the previous instruction.
      UpdateProgramCounter(-4);
      return_address_ = program_counter_ + 4;
      // If it is jalr, then jump to the address stored in the register.
      if (opcode==get_instr_encoding(Instruction::kjalr).opcode) { 
        UpdateProgramCounter(-program_counter_ + (execution_result_));
      // For jal, jump by the immediate offset.
      } else if (opcode==get_instr_encoding(Instruction::kjal).opcode) {
        UpdateProgramCounter(imm);
      }
      
      // Match with branching instructions.
    } else if (opcode==get_instr_encoding(Instruction::kbeq).opcode ||
               opcode==get_instr_encoding(Instruction::kbne).opcode ||
               opcode==get_instr_encoding(Instruction::kblt).opcode ||
               opcode==get_instr_encoding(Instruction::kbge).opcode ||
               opcode==get_instr_encoding(Instruction::kbltu).opcode ||
               opcode==get_instr_encoding(Instruction::kbgeu).opcode) {
      // Match the function exactly and check the conditions.
      switch (funct3) {
        case 0b000: {// BEQ
          branch_flag_ = (execution_result_==0);
          break;
        }
        case 0b001: {// BNE
          branch_flag_ = (execution_result_!=0);
          break;
        }
        case 0b100: {// BLT
          branch_flag_ = (execution_result_==1);
          break;
        }
        case 0b101: {// BGE
          branch_flag_ = (execution_result_==0);
          break;
        }
        case 0b110: {// BLTU
          branch_flag_ = (execution_result_==1);
          break;
        }
        case 0b111: {// BGEU
          branch_flag_ = (execution_result_==0);
          break;
        }
      }

    }



  }

  // Branch with the offset if condition is true.
  if (branch_flag_ && opcode==0b1100011) {
    UpdateProgramCounter(-4);
    UpdateProgramCounter(imm);
  }

  // AUIPC instruction.
  if (opcode==get_instr_encoding(Instruction::kauipc).opcode) { // AUIPC
    execution_result_ = static_cast<int64_t>(program_counter_) - 4 + (imm << 12);

  }
}

// Float execution.
void RVSSVM::ExecuteFloat() {
  // Get the opcode, funct3, funct7, rs2, rs1, rs3.
  // Some instructions like fmadd, fmsub have 3 source registers.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;
  uint8_t funct7 = (current_instruction_ >> 25) & 0b1111111;
  uint8_t rm = funct3;
  uint8_t rs1 = (current_instruction_ >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;
  uint8_t rs3 = (current_instruction_ >> 27) & 0b11111;

  uint8_t fcsr_status = 0;

  // Retrieve the immediate value.
  int32_t imm = ImmGenerator(current_instruction_);

  // Check for dynamic rounding of the result (fetch from CPU instead of sticking to a fixed type).
  if (rm==0b111) {
    rm = registers_.ReadCsr(0x002);
  }

  // Compute the register values.
  uint64_t reg1_value = registers_.ReadFpr(rs1);
  uint64_t reg2_value = registers_.ReadFpr(rs2);
  uint64_t reg3_value = registers_.ReadFpr(rs3);

  // Check if the opcodes match with instructions like fmv, fcvt, where rs1 is an integer register.
  // If so, then read it's value as an int, not a float.
  if (funct7==0b1101000 || funct7==0b1111000 || opcode==0b0000111 || opcode==0b0100111) {
    reg1_value = registers_.ReadGpr(rs1);
  }

  // Check if the second operand value comes from the immediate and not rs2.
  // Copy the immediate value into reg2_value if so.
  if (control_unit_.GetAluSrc()) {
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  // Determine the operation to be performed.
  alu::AluOp aluOperation = control_unit_.GetAluSignal(current_instruction_, control_unit_.GetAluOp());
  // Perform the operation.
  std::tie(execution_result_, fcsr_status) = alu::Alu::fpexecute(aluOperation, reg1_value, reg2_value, reg3_value, rm);

  // std::cout << "+++++ Float execution result: " << execution_result_ << std::endl;

  // Write the CSR status.
  registers_.WriteCsr(0x003, fcsr_status);
}

// Double Instruction Execution.
void RVSSVM::ExecuteDouble() {
  // Similar to float, load the necessary values.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;
  uint8_t funct7 = (current_instruction_ >> 25) & 0b1111111;
  uint8_t rm = funct3;
  uint8_t rs1 = (current_instruction_ >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;
  uint8_t rs3 = (current_instruction_ >> 27) & 0b11111;

  uint8_t fcsr_status = 0;

  // Load the immediate.
  int32_t imm = ImmGenerator(current_instruction_);

  // Load the float values of the source registers.
  uint64_t reg1_value = registers_.ReadFpr(rs1);
  uint64_t reg2_value = registers_.ReadFpr(rs2);
  uint64_t reg3_value = registers_.ReadFpr(rs3);

  // Check if the instruction uses int regs, update accordingly.
  if (funct7==0b1101001 || funct7==0b1111001 || opcode==0b0000111 || opcode==0b0100111) {
    reg1_value = registers_.ReadGpr(rs1);
  }

  // Check if second operance uses immediate, update accordingly.
  if (control_unit_.GetAluSrc()) {
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  // Determine the operation.
  alu::AluOp aluOperation = control_unit_.GetAluSignal(current_instruction_, control_unit_.GetAluOp());
  // Perform the operation.
  std::tie(execution_result_, fcsr_status) = alu::Alu::dfpexecute(aluOperation, reg1_value, reg2_value, reg3_value, rm);
}

// CSR execution. To be checked.
void RVSSVM::ExecuteCsr() {
  uint8_t rs1 = (current_instruction_ >> 15) & 0b11111;
  uint16_t csr = (current_instruction_ >> 20) & 0xFFF;
  uint64_t csr_val = registers_.ReadCsr(csr);

  csr_target_address_ = csr;
  csr_old_value_ = csr_val;
  csr_write_val_ = registers_.ReadGpr(rs1);
  csr_uimm_ = rs1;
}

// TODO: implement writeback for syscalls
void RVSSVM::HandleSyscall() {
  uint64_t syscall_number = registers_.ReadGpr(17);
  switch (syscall_number) {
    case SYSCALL_PRINT_INT: {
        if (!globals::vm_as_backend) {
            std::cout << "[Syscall output: ";
        } else {
          std::cout << "VM_STDOUT_START";
        }
        std::cout << static_cast<int64_t>(registers_.ReadGpr(10)); // Print signed integer
        if (!globals::vm_as_backend) {
            std::cout << "]" << std::endl;
        } else {
          std::cout << "VM_STDOUT_END" << std::endl;
        }
        break;
    }
    case SYSCALL_PRINT_FLOAT: { // print float
        if (!globals::vm_as_backend) {
            std::cout << "[Syscall output: ";
        } else {
          std::cout << "VM_STDOUT_START";
        }
        float float_value;
        uint64_t raw = registers_.ReadGpr(10);
        std::memcpy(&float_value, &raw, sizeof(float_value));
        std::cout << std::setprecision(std::numeric_limits<float>::max_digits10) << float_value;
        if (!globals::vm_as_backend) {
            std::cout << "]" << std::endl;
        } else {
          std::cout << "VM_STDOUT_END" << std::endl;
        }
        break;
    }
    case SYSCALL_PRINT_DOUBLE: { // print double
        if (!globals::vm_as_backend) {
            std::cout << "[Syscall output: ";
        } else {
          std::cout << "VM_STDOUT_START";
        }
        double double_value;
        uint64_t raw = registers_.ReadGpr(10);
        std::memcpy(&double_value, &raw, sizeof(double_value));
        std::cout << std::setprecision(std::numeric_limits<double>::max_digits10) << double_value;
        if (!globals::vm_as_backend) {
            std::cout << "]" << std::endl;
        } else {
          std::cout << "VM_STDOUT_END" << std::endl;
        }
        break;
    }
    case SYSCALL_PRINT_STRING: {
        if (!globals::vm_as_backend) {
            std::cout << "[Syscall output: ";
        }
        PrintString(registers_.ReadGpr(10)); // Print string
        if (!globals::vm_as_backend) {
            std::cout << "]" << std::endl;
        }
        break;
    }
    case SYSCALL_EXIT: {
        stop_requested_ = true; // Stop the VM
        if (!globals::vm_as_backend) {
            std::cout << "VM_EXIT" << std::endl;
        }
        output_status_ = "VM_EXIT";
        std::cout << "Exited with exit code: " << registers_.ReadGpr(10) << std::endl;
        exit(0); // Exit the program
        break;
    }
    case SYSCALL_READ: { // Read
      uint64_t file_descriptor = registers_.ReadGpr(10);
      uint64_t buffer_address = registers_.ReadGpr(11);
      uint64_t length = registers_.ReadGpr(12);

      if (file_descriptor == 0) {
        // Read from stdin
        std::string input;
        {
          std::cout << "VM_STDIN_START" << std::endl;
          output_status_ = "VM_STDIN_START";
          std::unique_lock<std::mutex> lock(input_mutex_);
          input_cv_.wait(lock, [this]() { 
            return !input_queue_.empty(); 
          });
          output_status_ = "VM_STDIN_END";
          std::cout << "VM_STDIN_END" << std::endl;

          input = input_queue_.front();
          input_queue_.pop();
        }


        std::vector<uint8_t> old_bytes_vec(length, 0);
        std::vector<uint8_t> new_bytes_vec(length, 0);

        for (size_t i = 0; i < length; ++i) {
          old_bytes_vec[i] = memory_controller_.ReadByte(buffer_address + i);
        }
        
        for (size_t i = 0; i < input.size() && i < length; ++i) {
          memory_controller_.WriteByte(buffer_address + i, static_cast<uint8_t>(input[i]));
        }
        if (input.size() < length) {
          memory_controller_.WriteByte(buffer_address + input.size(), '\0');
        }

        for (size_t i = 0; i < length; ++i) {
          new_bytes_vec[i] = memory_controller_.ReadByte(buffer_address + i);
        }

        current_delta_.memory_changes.push_back({
          buffer_address, 
          old_bytes_vec, 
          new_bytes_vec
        });

        uint64_t old_reg = registers_.ReadGpr(10);
        unsigned int reg_index = 10;
        unsigned int reg_type = 0; // 0 for GPR, 1 for CSR, 2 for FPR
        uint64_t new_reg = std::min(static_cast<uint64_t>(length), static_cast<uint64_t>(input.size()));
        registers_.WriteGpr(10, new_reg); 
        if (old_reg != new_reg) {
          current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
        }

      } else {
          std::cerr << "Unsupported file descriptor: " << file_descriptor << std::endl;
      }
      break;
    }
    case SYSCALL_WRITE: { // Write
        uint64_t file_descriptor = registers_.ReadGpr(10);
        uint64_t buffer_address = registers_.ReadGpr(11);
        uint64_t length = registers_.ReadGpr(12);

        if (file_descriptor == 1) { // stdout
          std::cout << "VM_STDOUT_START";
          output_status_ = "VM_STDOUT_START";
          uint64_t bytes_printed = 0;
          for (uint64_t i = 0; i < length; ++i) {
              char c = memory_controller_.ReadByte(buffer_address + i);
              // if (c == '\0') {
              //     break;
              // }
              std::cout << c;
              bytes_printed++;
          }
          std::cout << std::flush; 
          output_status_ = "VM_STDOUT_END";
          std::cout << "VM_STDOUT_END" << std::endl;

          uint64_t old_reg = registers_.ReadGpr(10);
          unsigned int reg_index = 10;
          unsigned int reg_type = 0; // 0 for GPR, 1 for CSR, 2 for FPR
          uint64_t new_reg = std::min(static_cast<uint64_t>(length), bytes_printed);
          registers_.WriteGpr(10, new_reg);
          if (old_reg != new_reg) {
            current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
          }
        } else {
            std::cerr << "Unsupported file descriptor: " << file_descriptor << std::endl;
        }
        break;
    }
    default: {
      std::cerr << "Unknown syscall number: " << syscall_number << std::endl;
      break;
    }
  }
}

// Execute the EX stage of the pipeline.
// handle the operation, perform ALU operations and then write the values to the
// EX_MEM register.
void RVSSvm::EX(){
  // Pass on the values that do not change.
  EX_MEM_REG.rs2_value = ID_EX_REG.rs2_value; // load/store.
  EX_MEM_REG.rd = ID_EX_REG.rd;
  EX_MEM_REG.mem_to_reg = ID_EX_REG.mem_to_reg;
  EX_MEM_REG.reg_write = ID_EX_REG.reg_write;
  EX_MEM_REG.mem_read = ID_EX_REG.mem_read;
  EX_MEM_REG.mem_write = ID_EX_REG.mem_write;
  EX_MEM_REG.branch = ID_EX_REG.branch;
  EX_MEM_REG.opcode = ID_EX_REG.opcode;
  EX_MEM_REG.funct3 = ID_EX_REG.funct3;
  EX_MEM_REG.funct7 = ID_EX_REG.funct7;
  EX_MEM_REG.imm = ID_EX_REG.imm;

  // Do the required operations.
  // Only considering integer registers for now.
  uint8_t opcode = ID_EX_REG.opcode;
  uint8_t funct3 = ID_EX_REG.funct3;

  int32_t imm = ID_EX_REG.imm;

  uint64_t reg1_value = ID_EX_REG.rs1_value;
  uint64_t reg2_value = ID_EX_REG.rs2_value;

  bool overflow = false;

  if(ID_EX_REG.alu_src){
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  std::tie(execution_result_, overflow) = alu::Alu::fpexecute(ID_EX_REG.alu_operation, reg1_value, reg2_value);

  EX_MEM_REG.alu_result = execution_result_

  if (opcode==get_instr_encoding(Instruction::kauipc).opcode) { // AUIPC
    execution_result_ = static_cast<int64_t>(ID_EX_REG.pc) - 4 + (imm << 12);
  }
}

// Write to memory (MEM stage).
void RVSSVM::WriteMemory() {
  // Get the opcode, rs2 and funct3 of the instruction.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;

  // Check for ecall/ebreak.
  if (opcode == 0b1110011 && funct3 == 0b000) {
    return;
  }

  // Handle F/D instructions separately.
  if (instruction_set::isFInstruction(current_instruction_)) { // RV64 F
    WriteMemoryFloat();
    return;
  } else if (instruction_set::isDInstruction(current_instruction_)) {
    WriteMemoryDouble();
    return;
  }

  // If the instruction is to load data from memory.
  if (control_unit_.GetMemRead()) {
    // Check the function type and act accordingly.
    switch (funct3) {
      case 0b000: {// LB
        memory_result_ = static_cast<int8_t>(memory_controller_.ReadByte(execution_result_));
        break;
      }
      case 0b001: {// LH
        memory_result_ = static_cast<int16_t>(memory_controller_.ReadHalfWord(execution_result_));
        break;
      }
      case 0b010: {// LW
        memory_result_ = static_cast<int32_t>(memory_controller_.ReadWord(execution_result_));
        break;
      }
      case 0b011: {// LD
        memory_result_ = memory_controller_.ReadDoubleWord(execution_result_);
        break;
      }
      case 0b100: {// LBU
        memory_result_ = static_cast<uint8_t>(memory_controller_.ReadByte(execution_result_));
        break;
      }
      case 0b101: {// LHU
        memory_result_ = static_cast<uint16_t>(memory_controller_.ReadHalfWord(execution_result_));
        break;
      }
      case 0b110: {// LWU
        memory_result_ = static_cast<uint32_t>(memory_controller_.ReadWord(execution_result_));
        break;
      }
    }
  }

  uint64_t addr = 0;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

  // TODO: use direct read to read memory for undo/redo functionality, i.e. ReadByte -> ReadByte_d

  // If instruction type is to write to memory.
  if (control_unit_.GetMemWrite()) {
    // Match the opcode and act accordingly.
    switch (funct3) {
      case 0b000: {// SB
        // Find the memory address.
        addr = execution_result_;
        // Store the current byte at that position - useful for undo/redo.
        old_bytes_vec.push_back(memory_controller_.ReadByte(addr));
        // Write the new byte to the location.
        memory_controller_.WriteByte(execution_result_, registers_.ReadGpr(rs2) & 0xFF);
        // Store the new byte for redo functionality.
        new_bytes_vec.push_back(memory_controller_.ReadByte(addr));
        break;
      }
      case 0b001: {// SH
        // Same thing as the first case repeated elsewhere, only here we use an offset to loop through the bytes.
        addr = execution_result_;
        for (size_t i = 0; i < 2; ++i) {
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteHalfWord(execution_result_, registers_.ReadGpr(rs2) & 0xFFFF);
        for (size_t i = 0; i < 2; ++i) {
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
      case 0b010: {// SW
        addr = execution_result_;
        for (size_t i = 0; i < 4; ++i) {
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteWord(execution_result_, registers_.ReadGpr(rs2) & 0xFFFFFFFF);
        for (size_t i = 0; i < 4; ++i) {
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
      case 0b011: {// SD
        addr = execution_result_;
        for (size_t i = 0; i < 8; ++i) {
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteDoubleWord(execution_result_, registers_.ReadGpr(rs2) & 0xFFFFFFFFFFFFFFFF);
        for (size_t i = 0; i < 8; ++i) {
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
    }
  }

  // If we have a change, then push the changes.
  if (old_bytes_vec != new_bytes_vec) {
    current_delta_.memory_changes.push_back({
      addr,
      old_bytes_vec,
      new_bytes_vec
    });
  }
}

// Memory access for float.
void RVSSVM::WriteMemoryFloat() {
  // Get rs2.
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;

  // flw instruction.
  if (control_unit_.GetMemRead()) { // FLW
    memory_result_ = memory_controller_.ReadWord(execution_result_);
  }

  // std::cout << "+++++ Memory result: " << memory_result_ << std::endl;

  uint64_t addr = 0;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

  // Store the float into memory, similar to integer register.
  if (control_unit_.GetMemWrite()) { // FSW
    addr = execution_result_;
    for (size_t i = 0; i < 4; ++i) {
      old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
    uint32_t val = registers_.ReadFpr(rs2) & 0xFFFFFFFF;
    memory_controller_.WriteWord(execution_result_, val);
    // new_bytes_vec.push_back(memory_controller_.ReadByte(addr));
    for (size_t i = 0; i < 4; ++i) {
      new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
  }

  if (old_bytes_vec!=new_bytes_vec) {
    current_delta_.memory_changes.push_back({addr, old_bytes_vec, new_bytes_vec});
  }
}

// Memory access for double, same as float.
void RVSSVM::WriteMemoryDouble() {
  uint8_t rs2 = (current_instruction_ >> 20) & 0b11111;

  if (control_unit_.GetMemRead()) {// FLD
    memory_result_ = memory_controller_.ReadDoubleWord(execution_result_);
  }

  uint64_t addr = 0;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

  if (control_unit_.GetMemWrite()) {// FSD
    addr = execution_result_;
    for (size_t i = 0; i < 8; ++i) {
      old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
    memory_controller_.WriteDoubleWord(execution_result_, registers_.ReadFpr(rs2));
    for (size_t i = 0; i < 8; ++i) {
      new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
  }

  if (old_bytes_vec!=new_bytes_vec) {
    current_delta_.memory_changes.push_back({addr, old_bytes_vec, new_bytes_vec});
  }
}

void RVSSVM::MEM(){
  MEM_WB_REG.alu_result = EX_MEM_REG.alu_result;
  MEM_WB_REG.rd = EX_MEM_REG.rd;
  MEM_WB_REG.mem_to_reg = EX_MEM_REG.mem_to_reg;
  MEM_WB_REG.reg_write = EX_MEM_REG.reg_write;
  MEM_WB_REG.opcode = EX_MEM_REG.opcode;
  MEM_WB_REG.funct3 = EX_MEM_REG.funct3;
  MEM_WB_REG.imm = EX_MEM_REG.imm;

  uint8_t opcode = EX_MEM_REG.opcode;
  uint8_t funct3 = EX_MEM_REG.funct3;

  if(EX_MEM_REG.branch){
    uint64_t pc = EX_MEM_REG.pc
    if (opcode==get_instr_encoding(Instruction::kjalr).opcode ||
        opcode==get_instr_encoding(Instruction::kjal).opcode) {

      // Store the return point.
      MEM_WB_REG.pc = static_cast<int64_t>(pc); // PC was already updated in Fetch()
      // Go back to the previous instruction.
      UpdateProgramCounter(-4);
      return_address_ = program_counter_ + 4;
      // If it is jalr, then jump to the address stored in the register.
      if (opcode==get_instr_encoding(Instruction::kjalr).opcode) {
        UpdateProgramCounter(-program_counter_ + (execution_result_));
      // For jal, jump by the immediate offset.
      } else if (opcode==get_instr_encoding(Instruction::kjal).opcode) {
        UpdateProgramCounter(imm);
      }
  }

  if(opcode == 0b1110011 && funct3 == 0b000){
    return;
  }
  // Ignoring F/D instructions for now.

  uint64_t addr = EX_MEM_REG.alu_result;

  if(EX_MEM_REG.mem_read){
    switch(funct3){
      case 0b000: {
        memory_result_ = static_cast<int8_t>(memory_controller_.ReadByte(addr));
        break;
      }
      case 0b001: {
        memory_result_ = static_cast<int16_t>(memory_controller_.ReadHalfWord(addr));
        break;
      }
      case 0b010: {
        memory_result_ = static_cast<int32_t>(memory_controller_.ReadWord(addr));
        break;
      }
      case 0b011: {
        memory_result_ = memory_controller_.ReadDoubleWord(addr);
        break;
      }
      case 0b100: {
        memory_result_ = static_cast<uint8_t>(memory_controller_.ReadByte(addr));
        break;
      }
      case 0b101: {
        memory_result_ = static_cast<uint16_t>(memory_controller_.ReadHalfWord(addr));
        break;
      }
      case 0b110: {
        memory_result_ = static_cast<uint32_t>(memory_controller_.ReadWord(addr));
        break;
      }
    }

    MEM_WB_REG.mem_result = memory_result_
  }

  if(EX_MEM_REG.mem_write){
    uint64_t target = EX_MEM_REG.rs2_value;
    switch(funct3){
      case 0b000: {
        old_bytes_vec.push_back(memory_controller_.ReadByte(addr));
        memory_controller_.WriteByte(addr, target & 0xFF);
        new_bytes_vec.push_back(memory_controller_.ReadByte(addr));
        break;
      }
      case 0b001: {
        for(size_t i = 0; i < 2 ; ++i){
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteHalfWord(addr, target & 0xFFFF);
        for(size_t i=0; i<2; i++){
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
      case 0b010: {
        for(size_t i = 0; i < 4 ; ++i){
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteWord(addr, target & 0xFFFFFFFF);
        for(size_t i=0; i<4; i++){
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
      case 0b011: {
        for(size_t i = 0; i < 8 ; ++i){
          old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        memory_controller_.WriteDoubleWord(addr, target & 0xFFFFFFFFFFFFFFFF);
        for(size_t i=0; i<8; i++){
          new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
        }
        break;
      }
    }
  }

  if(old_bytes_vec != new_bytes_vec){
    current_delta_.memory_changes.push_back({
      addr,
      old_bytes_vec,
      new_bytes_vec
    });
  }
}

// Write back to register file (WB stage).
void RVSSVM::WriteBack() {
  // Load the opcode, funct3, rm and immediate.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;
  uint8_t rd = (current_instruction_ >> 7) & 0b11111;
  int32_t imm = ImmGenerator(current_instruction_);

  if (opcode == get_instr_encoding(Instruction::kecall).opcode && 
      funct3 == get_instr_encoding(Instruction::kecall).funct3) { // ecall
    return;
  }

  // Separate handling for F/D/CSR.
  if (instruction_set::isFInstruction(current_instruction_)) { // RV64 F
    WriteBackFloat();
    return;
  } else if (instruction_set::isDInstruction(current_instruction_)) {
    WriteBackDouble();
    return;
  } else if (opcode==0b1110011) { // CSR opcode
    WriteBackCsr();
    return;
  }

  // Get rd.
  uint64_t old_reg = registers_.ReadGpr(rd);
  unsigned int reg_index = rd;
  unsigned int reg_type = 0; // 0 for GPR, 1 for CSR, 2 for FPR

  // Writing to the register.
  if (control_unit_.GetRegWrite()) { 
    switch (opcode) {
      // For R/I/AIUPC write the execution result to rd.
      case get_instr_encoding(Instruction::kRtype).opcode: /* R-Type */
      case get_instr_encoding(Instruction::kItype).opcode: /* I-Type */
      case get_instr_encoding(Instruction::kauipc).opcode: /* AUIPC */ {
        registers_.WriteGpr(rd, execution_result_);
        break;
      }
      // For load type, write the value loaded from memory.
      case get_instr_encoding(Instruction::kLoadType).opcode: /* Load */ { 
        registers_.WriteGpr(rd, memory_result_);
        break;
      }
      // For jal/jalr write the value of PC.
      case get_instr_encoding(Instruction::kjalr).opcode: /* JALR */
      case get_instr_encoding(Instruction::kjal).opcode: /* JAL */ {
        registers_.WriteGpr(rd, next_pc_);
        break;
      }
      // For LUI, write the immediate shifted by 12 bits.
      case get_instr_encoding(Instruction::klui).opcode: /* LUI */ {
        registers_.WriteGpr(rd, (imm << 12));
        break;
      }
      default: break;
    }
  }

  if (opcode==get_instr_encoding(Instruction::kjal).opcode) /* JAL */ {
    // Updated in Execute()
  }
  if (opcode==get_instr_encoding(Instruction::kjalr).opcode) /* JALR */ {
    // registers_.WriteGpr(rd, return_address_); // Write back to rs1
    // Updated in Execute()
  }

  // Store the new reg value.
  uint64_t new_reg = registers_.ReadGpr(rd);
  // Push changes.
  if (old_reg!=new_reg) {
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }

}

// Register writing for float.
void RVSSVM::WriteBackFloat() {
  // Load up opcode, funct7, rd.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t funct7 = (current_instruction_ >> 25) & 0b1111111;
  uint8_t rd = (current_instruction_ >> 7) & 0b11111;

  uint64_t old_reg = 0;
  unsigned int reg_index = rd;
  unsigned int reg_type = 2; // 0 for GPR, 1 for CSR, 2 for FPR
  uint64_t new_reg = 0;

  // Check if we are writing to the register.
  if (control_unit_.GetRegWrite()) {
    switch(funct7) {
      // write to GPR for comparison/conversion/moving to int reg.
      case get_instr_encoding(Instruction::kfle_s).funct7: // f(eq|lt|le).s
      case get_instr_encoding(Instruction::kfcvt_w_s).funct7: // fcvt.(w|wu|l|lu).s
      case get_instr_encoding(Instruction::kfmv_x_w).funct7: // fmv.x.w , fclass.s
      {
        old_reg = registers_.ReadGpr(rd);
        registers_.WriteGpr(rd, execution_result_);
        new_reg = execution_result_;
        reg_type = 0; // GPR
        break;
      }

      // write to FPR for other instructions.
      default: {
        switch (opcode) {
          // Write from memory for laod type.
          case get_instr_encoding(Instruction::kflw).opcode: {
            old_reg = registers_.ReadFpr(rd);
            registers_.WriteFpr(rd, memory_result_);
            new_reg = memory_result_;
            reg_type = 2; // FPR
            break;
          }
          // Write from ALU for others.
          default: {
            old_reg = registers_.ReadFpr(rd);
            registers_.WriteFpr(rd, execution_result_);
            new_reg = execution_result_;
            reg_type = 2; // FPR
            break;
          }
        }
      }
    }

    // // write to GPR
    // if (funct7==0b1010000
    //     || funct7==0b1100000
    //     || funct7==0b1110000) { // f(eq|lt|le).s, fcvt.(w|wu|l|lu).s
    //   old_reg = registers_.ReadGpr(rd);
    //   registers_.WriteGpr(rd, execution_result_);
    //   new_reg = execution_result_;
    //   reg_type = 0; // GPR

    // }
    // // write to FPR
    // else if (opcode==get_instr_encoding(Instruction::kflw).opcode) {
    //   old_reg = registers_.ReadFpr(rd);
    //   registers_.WriteFpr(rd, memory_result_);
    //   new_reg = memory_result_;
    //   reg_type = 2; // FPR
    // } else {
    //   old_reg = registers_.ReadFpr(rd);
    //   registers_.WriteFpr(rd, execution_result_);
    //   new_reg = execution_result_;
    //   reg_type = 2; // FPR
    // }
  }

  // Push changes.
  if (old_reg!=new_reg) {
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }
}

// Memory access for double, similar to float.
void RVSSVM::WriteBackDouble() {
  // Load opcode, funct7, rd.
  uint8_t opcode = current_instruction_ & 0b1111111;
  uint8_t funct7 = (current_instruction_ >> 25) & 0b1111111;
  uint8_t rd = (current_instruction_ >> 7) & 0b11111;

  uint64_t old_reg = 0;
  unsigned int reg_index = rd;
  unsigned int reg_type = 2; // 0 for GPR, 1 for CSR, 2 for FPR
  uint64_t new_reg = 0;

  // Check if we are writing.
  if (control_unit_.GetRegWrite()) {
    // write to GPR for comparison, conversion, moving.
    if (funct7==0b1010001
        || funct7==0b1100001
        || funct7==0b1110001) { // f(eq|lt|le).d, fcvt.(w|wu|l|lu).d
      old_reg = registers_.ReadGpr(rd);
      registers_.WriteGpr(rd, execution_result_);
      new_reg = execution_result_;
      reg_type = 0; // GPR
    }
      // write to FPR
    else if (opcode==0b0000111) {
      // Write from memory for loading.
      old_reg = registers_.ReadFpr(rd);
      registers_.WriteFpr(rd, memory_result_);
      new_reg = memory_result_;
      reg_type = 2; // FPR
    } else {
      // Write from ALU otherwise.
      old_reg = registers_.ReadFpr(rd);
      registers_.WriteFpr(rd, execution_result_);
      new_reg = execution_result_;
      reg_type = 2; // FPR
    }
  }

  // Push changes.
  if (old_reg!=new_reg) {
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }

  return;
}

// CSR writing.
void RVSSVM::WriteBackCsr() {
  uint8_t rd = (current_instruction_ >> 7) & 0b11111;
  uint8_t funct3 = (current_instruction_ >> 12) & 0b111;

  switch (funct3) {
    case get_instr_encoding(Instruction::kcsrrw).funct3: { // CSRRW
      registers_.WriteGpr(rd, csr_old_value_);
      registers_.WriteCsr(csr_target_address_, csr_write_val_);
      break;
    }
    case get_instr_encoding(Instruction::kcsrrs).funct3: { // CSRRS
      registers_.WriteGpr(rd, csr_old_value_);
      if (csr_write_val_!=0) {
        registers_.WriteCsr(csr_target_address_, csr_old_value_ | csr_write_val_);
      }
      break;
    }
    case get_instr_encoding(Instruction::kcsrrc).funct3: { // CSRRC
      registers_.WriteGpr(rd, csr_old_value_);
      if (csr_write_val_!=0) {
        registers_.WriteCsr(csr_target_address_, csr_old_value_ & ~csr_write_val_);
      }
      break;
    }
    case get_instr_encoding(Instruction::kcsrrwi).funct3: { // CSRRWI
      registers_.WriteGpr(rd, csr_old_value_);
      registers_.WriteCsr(csr_target_address_, csr_uimm_);
      break;
    }
    case get_instr_encoding(Instruction::kcsrrsi).funct3: { // CSRRSI
      registers_.WriteGpr(rd, csr_old_value_);
      if (csr_uimm_!=0) {
        registers_.WriteCsr(csr_target_address_, csr_old_value_ | csr_uimm_);
      }
      break;
    }
    case get_instr_encoding(Instruction::kcsrrci).funct3: { // CSRRCI
      registers_.WriteGpr(rd, csr_old_value_);
      if (csr_uimm_!=0) {
        registers_.WriteCsr(csr_target_address_, csr_old_value_ & ~csr_uimm_);
      }
      break;
    }
  }

}

void RVSSVM::WB(){
  uint8_t opcode = MEM_WB_REG.opcode;
  uint8_t funct3 = MEM_WB_REG.funct3;
  uint8_t rd = MEM_WB_REG.rd;
  int32_t imm = MEM_WB_REG.imm;

  if(opcode == get_instr_encoding(Instruction::kecall).opcode &&
    funct3 == get_instr_encoding(Instruction::kecall).funct3) {
    return;
  }
  
  // Ignore F/D for now.

  uint64_t old_reg = registers_.ReadGpr(rd);
  unsigned int reg_index = rd;
  unsigned int reg_type = 0;

  if(MEM_WB_REG.reg_write){
    switch(opcode){
      case get_instr_encoding(Instruction::kRtype).opcode:
      case get_instr_encoding(Instruction::kItype).opcode:
      case get_instr_encoding(Instruction::kauipc).opcode: {
        registers_.WriteGpr(rd, MEM_WB_REG.alu_result);
        break;
      }
      case get_instr_encoding(Instruction::kLoadType).opcode: {
        registers_.WriteGpr(rd, MEM_WB_REG.mem_result);
        break;
      }
      case get_instr_encoding(Instruction::kjalr).opcode:
      case get_instr_encoding(Instruction::kjal).opcode: {
        registers_.WriteGpr(rd, MEM_WB_REG.pc);
        break;
      }
      case get_instr_encoding(Instruction::klui).opcode: {
        registers_.WriteGpr(rd, (MEM_WB_REG.imm << 12));
        break;
      }
      default: break;
    }
  }

  uint64_t new_reg = registers_.ReadGpr(rd);
  if(old_reg!=new_reg){
    current_delta_.register_changes.push_back({reg_index, reg_type, old_type, new_reg});
  }
}

// RUN.
void RVSSVM::Run() {
  // Clear the stop flag, clearing the VM to run.
  ClearStop();
  // Number of instructions executed.
  uint64_t instruction_executed = 0;

  // Keep going as long as we don't want to stop or PC exceeds the max program size.
  while (!stop_requested_ && program_counter_ < program_size_) {
    // Check if max instructions are exceeded.
    if (instruction_executed > vm_config::config.getInstructionExecutionLimit())
      break;

    // Fetch the instruction.
    Fetch();
    // Decode the instruction.
    Decode();
    // Execute the operation.
    Execute();
    // Access memory.
    WriteMemory();
    // Write to register file.
    WriteBack();
    // Increment the insturction counters and cycles.
    instructions_retired_++;
    instruction_executed++;
    cycle_s_++;
    // Log the PC.
    std::cout << "Program Counter: " << program_counter_ << std::endl;
  }
  if (program_counter_ >= program_size_) {
    std::cout << "VM_PROGRAM_END" << std::endl;
    output_status_ = "VM_PROGRAM_END";
  }
  // DUmp the register and memory states.
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Run with debugging.
void RVSSVM::DebugRun() {
  // Clear the VM to run.
  ClearStop();
  // Instructions executed.
  uint64_t instruction_executed = 0;
  // Keep iterating until EOF or exceeding program size.
  while (!stop_requested_ && program_counter_ < program_size_) {
    if (instruction_executed > vm_config::config.getInstructionExecutionLimit())
      break;
    // Store old PC (for undo/redo).
    current_delta_.old_pc = program_counter_;
    
    // Breakpoint check.
    if (std::find(breakpoints_.begin(), breakpoints_.end(), program_counter_) == breakpoints_.end()) {
      // Execute normally.
      Fetch();
      Decode();
      Execute();
      WriteMemory();
      WriteBack();
      instructions_retired_++;
      instruction_executed++;
      cycle_s_++;
      std::cout << "Program Counter: " << program_counter_ << std::endl;

      // Store the new PC.
      current_delta_.new_pc = program_counter_;
      // history_.push(current_delta_);
      // Push into undo stack.
      undo_stack_.push(current_delta_);
      while (!redo_stack_.empty()) {
        redo_stack_.pop();
      }
      current_delta_ = StepDelta();
      // Step reporting.
      if (program_counter_ < program_size_) {
        std::cout << "VM_STEP_COMPLETED" << std::endl;
        output_status_ = "VM_STEP_COMPLETED";
      } else if (program_counter_ >= program_size_) {
        std::cout << "VM_LAST_INSTRUCTION_STEPPED" << std::endl;
        output_status_ = "VM_LAST_INSTRUCTION_STEPPED";
      }
      // Dump states.
      DumpRegisters(globals::registers_dump_file_path, registers_);
      DumpState(globals::vm_state_dump_file_path);

      // Add a pause between the steps.
      unsigned int delay_ms = vm_config::config.getRunStepDelay();
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
      
    } else {
      // On hitting a breakpoint.
      std::cout << "VM_BREAKPOINT_HIT " << program_counter_ << std::endl;
      output_status_ = "VM_BREAKPOINT_HIT";
      break;
    }
  }
  if (program_counter_ >= program_size_) {
    std::cout << "VM_PROGRAM_END" << std::endl;
    output_status_ = "VM_PROGRAM_END";
  }
  // Dump state.
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Take a single step.
void RVSSVM::Step() {
  // Store the old PC.
  current_delta_.old_pc = program_counter_;
  // Go forward if permitted.
  if (program_counter_ < program_size_) {
    // Execute for one cycle.
    Fetch();
    Decode();
    Execute();
    WriteMemory();
    WriteBack();
    instructions_retired_++;
    cycle_s_++;
    std::cout << "Program Counter: " << std::hex << program_counter_ << std::dec << std::endl;

    current_delta_.new_pc = program_counter_;

    // history_.push(current_delta_);

    undo_stack_.push(current_delta_);
    while (!redo_stack_.empty()) {
      redo_stack_.pop();
    }

    current_delta_ = StepDelta();


    if (program_counter_ < program_size_) {
      std::cout << "VM_STEP_COMPLETED" << std::endl;
      output_status_ = "VM_STEP_COMPLETED";
    } else if (program_counter_ >= program_size_) {
      std::cout << "VM_LAST_INSTRUCTION_STEPPED" << std::endl;
      output_status_ = "VM_LAST_INSTRUCTION_STEPPED";
    }

  } else if (program_counter_ >= program_size_) {
    std::cout << "VM_PROGRAM_END" << std::endl;
    output_status_ = "VM_PROGRAM_END";
  }
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Undo the step.
void RVSSVM::Undo() {
  // Empty stack check.
  if (undo_stack_.empty()) {
    std::cout << "VM_NO_MORE_UNDO" << std::endl;
    output_status_ = "VM_NO_MORE_UNDO";
    return;
  }
  // Get the last set of changes.
  StepDelta last = undo_stack_.top();
  undo_stack_.pop();

  // if (!history_.can_undo()) {
  //     std::cout << "Nothing to undo.\n";
  //     return;
  // }

  // StepDelta last = history_.undo();

  // Write changes to registers.
  for (const auto &change : last.register_changes) {
    switch (change.reg_type) {
      case 0: { // GPR
        registers_.WriteGpr(change.reg_index, change.old_value);
        break;
      }
      case 1: { // CSR
        registers_.WriteCsr(change.reg_index, change.old_value);
        break;
      }
      case 2: { // FPR
        registers_.WriteFpr(change.reg_index, change.old_value);
        break;
      }
      default:std::cerr << "Invalid register type: " << change.reg_type << std::endl;
        break;
    }
  }

  // Write changes to memory.
  for (const auto &change : last.memory_changes) {
    for (size_t i = 0; i < change.old_bytes_vec.size(); ++i) {
      memory_controller_.WriteByte(change.address + i, change.old_bytes_vec[i]);
    }
  }

  // Restore PC, instruction count and cycles.
  program_counter_ = last.old_pc;
  instructions_retired_--;
  cycle_s_--; 
  std::cout << "Program Counter: " << program_counter_ << std::endl;

  // Push the previous state to the redo stack.
  redo_stack_.push(last);

  output_status_ = "VM_UNDO_COMPLETED";
  std::cout << "VM_UNDO_COMPLETED" << std::endl;

  // Dump state.
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Redo the step.
void RVSSVM::Redo() {
  // Empty stack check.
  if (redo_stack_.empty()) {
    std::cout << "VM_NO_MORE_REDO" << std::endl;
    return;
  }

  // Get te change.
  StepDelta next = redo_stack_.top();
  redo_stack_.pop();

  // if (!history_.can_redo()) {
  //       std::cout << "Nothing to redo.\n";
  //       return;
  //   }

  //   StepDelta next = history_.redo();

  // Write register changes.
  for (const auto &change : next.register_changes) {
    switch (change.reg_type) {
      case 0: { // GPR
        registers_.WriteGpr(change.reg_index, change.new_value);
        break;
      }
      case 1: { // CSR
        registers_.WriteCsr(change.reg_index, change.new_value);
        break;
      }
      case 2: { // FPR
        registers_.WriteFpr(change.reg_index, change.new_value);
        break;
      }
      default:std::cerr << "Invalid register type: " << change.reg_type << std::endl;
        break;
    }
  }

  // Write memory changes.
  for (const auto &change : next.memory_changes) {
    for (size_t i = 0; i < change.new_bytes_vec.size(); ++i) {
      memory_controller_.WriteByte(change.address + i, change.new_bytes_vec[i]);
    }
  }

  // Update PC and other variables.
  program_counter_ = next.new_pc;
  instructions_retired_++;
  cycle_s_++;
  // Dump state.
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
  std::cout << "Program Counter: " << program_counter_ << std::endl;
  // Push the state to undo stack.
  undo_stack_.push(next);

}

// Reset the VM.
void RVSSVM::Reset() {
  // Reset all variables to 0.
  program_counter_ = 0;
  instructions_retired_ = 0;
  cycle_s_ = 0;
  registers_.Reset();
  memory_controller_.Reset();
  control_unit_.Reset();
  branch_flag_ = false;
  next_pc_ = 0;
  execution_result_ = 0;
  memory_result_ = 0;

  return_address_ = 0;
  csr_target_address_ = 0;
  csr_old_value_ = 0;
  csr_write_val_ = 0;
  csr_uimm_ = 0;
  current_delta_.register_changes.clear();
  current_delta_.memory_changes.clear();
  current_delta_.old_pc = 0;
  current_delta_.new_pc = 0;
  undo_stack_ = std::stack<StepDelta>();
  redo_stack_ = std::stack<StepDelta>();

}





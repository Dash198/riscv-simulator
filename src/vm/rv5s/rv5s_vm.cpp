/**
 * @file rvss_vm.cpp
 * @brief RV5S VM implementation
 * @author Vishank Singh, https://github.com/VishankSingh
 */

#include "vm/rv5s/rv5s_vm.h"

#include "utils.h"
#include "globals.h"
#include "common/instructions.h"
#include "config.h"

#include <cctype>
#include <climits>
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
RV5SVM::RV5SVM() : VmBase() {
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Initialise the desructor.
RV5SVM::~RV5SVM() = default;

// Execute the IF stage of the pipeline.
// Fetch the next insturction and send it with PC to the IF_ID register.
void RV5SVM::IF(){
  if(program_counter_ < program_size_){
    IF_ID_REG.instruction = memory_controller_.ReadWord(program_counter_);
    IF_ID_REG.pc = program_counter_;
    IF_ID_REG.isEmpty = false;
    UpdateProgramCounter(4);
  }
  else{
    IF_ID_REG.isEmpty = true;
  }

}

// Execute the ID stage for the pipeline.
// Find out the register valyes, the immediate and the required contorl signals.
// Store them in the ID_EX register.
void RV5SVM::ID(){
  if(IF_ID_REG.isEmpty){
    ID_EX_REG.isEmpty = true;
    return;
  }
  if(ID_EX_REG.isEmpty && !IF_ID_REG.isEmpty){
    ID_EX_REG.isEmpty = false;
  }
  // Pass on the PC to the next reg.
  ID_EX_REG.pc = IF_ID_REG.pc;
  
  uint64_t current_instruction = IF_ID_REG.instruction;

  // Assign their values.
  ID_EX_REG.imm = ImmGenerator(current_instruction);

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
  ID_EX_REG.alu_operation = control_unit_.GetAluSignal(current_instruction, control_unit_.GetAluOp());
  ID_EX_REG.isFloat = false;
  ID_EX_REG.isDouble = false;

  // Forward the instruction information.
  ID_EX_REG.opcode = current_instruction & 0b1111111;
  ID_EX_REG.funct3 = (current_instruction >> 12) & 0b111;
  ID_EX_REG.funct7 = (current_instruction >> 25) & 0b1111111;

  if(instruction_set::isFInstruction(current_instruction)){
    ID_EX_REG.isFloat = true;
    IDFP();
    return;
  }
  if(instruction_set::isDInstruction(current_instruction)){
    ID_EX_REG.isDouble = true;
    IDFP();
    return;
  }
  // Find rs1 and rs2.
  uint8_t rs1 = (current_instruction >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction >> 20) & 0b11111;
  ID_EX_REG.rs1_value = registers_.ReadGpr(rs1);
  ID_EX_REG.rs2_value = registers_.ReadGpr(rs2);
}

void RV5SVM::IDFP(){
  uint64_t current_instruction = IF_ID_REG.instruction;
  uint8_t rs1 = (current_instruction >> 15) & 0b11111;
  uint8_t rs2 = (current_instruction >> 20) & 0b11111;
  uint8_t rs3 = (current_instruction >> 27) & 0b11111;

  uint8_t opcode = ID_EX_REG.opcode;
  uint8_t funct7 = ID_EX_REG.funct7;
  ID_EX_REG.rs1_value = registers_.ReadFpr(rs1);
  if (funct7==0b1101000 || funct7==0b1111000 || funct7==0b1101001 || funct7==0b1111001 || opcode==0b0000111 || opcode==0b0100111) {
    ID_EX_REG.rs1_value = registers_.ReadGpr(rs1);
  }
  if(ID_EX_REG.funct3 == 0b111){
    ID_EX_REG.rm = registers_.ReadCsr(0x002); 
  }
  ID_EX_REG.rs2_value = registers_.ReadFpr(rs2);
  ID_EX_REG.rs3_value = registers_.ReadFpr(rs3);
}

// CSR execution. To be checked.
void RV5SVM::ExecuteCsr() {
  uint8_t rs1 = (current_instruction_ >> 15) & 0b11111;
  uint16_t csr = (current_instruction_ >> 20) & 0xFFF;
  uint64_t csr_val = registers_.ReadCsr(csr);

  csr_target_address_ = csr;
  csr_old_value_ = csr_val;
  csr_write_val_ = registers_.ReadGpr(rs1);
  csr_uimm_ = rs1;
}

// TODO: implement writeback for syscalls
void RV5SVM::HandleSyscall() {
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
void RV5SVM::EX(){
  if(ID_EX_REG.isEmpty){
    EX_MEM_REG.isEmpty = true;
    return;
  }
  if(EX_MEM_REG.isEmpty && !ID_EX_REG.isEmpty){
    EX_MEM_REG.isEmpty = false;
  }
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
  EX_MEM_REG.isFloat = false;
  EX_MEM_REG.isDouble = false;

  if(ID_EX_REG.isFloat){
    EX_MEM_REG.isFloat = true;
    EXF();
    return;
  }
  if(ID_EX_REG.isDouble){
    EX_MEM_REG.isDouble = true;
    EXD();
    return;
  }

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

  std::tie(execution_result_, overflow) = alu::Alu::execute(ID_EX_REG.alu_operation, reg1_value, reg2_value);

  if (opcode==get_instr_encoding(Instruction::kauipc).opcode) { // AUIPC
    execution_result_ = static_cast<int64_t>(ID_EX_REG.pc) - 4 + (imm << 12);
  }

  EX_MEM_REG.alu_result = execution_result_;
}

void RV5SVM::EXF(){
  uint8_t opcode = ID_EX_REG.opcode;
  uint8_t funct3 = ID_EX_REG.funct3;
  uint8_t funct7 = ID_EX_REG.funct7;
  uint8_t rm = funct3;

  uint8_t fcsr_status = 0;

  int32_t imm = ID_EX_REG.imm;

  uint64_t reg1_value = ID_EX_REG.rs1_value;
  uint64_t reg2_value = ID_EX_REG.rs2_value;
  uint64_t reg3_value = ID_EX_REG.rs3_value;

  if(ID_EX_REG.alu_src){
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  std::tie(execution_result_, fcsr_status) = alu::Alu::fpexecute(ID_EX_REG.alu_operation, reg1_value, reg2_value, reg3_value, rm);
  EX_MEM_REG.alu_result = execution_result_;
  EX_MEM_REG.fcsr_status = fcsr_status;
  registers_.WriteCsr(0x003, fcsr_status);
}

void RV5SVM::EXD(){
  uint8_t opcode = ID_EX_REG.opcode;
  uint8_t funct3 = ID_EX_REG.funct3;
  uint8_t funct7 = ID_EX_REG.funct7;
  uint8_t rm = funct3;

  uint8_t fcsr_status = 0;

  int32_t imm = ID_EX_REG.imm;

  uint64_t reg1_value = ID_EX_REG.rs1_value;
  uint64_t reg2_value = ID_EX_REG.rs2_value;
  uint64_t reg3_value = ID_EX_REG.rs3_value;

  if(ID_EX_REG.alu_src){
    reg2_value = static_cast<uint64_t>(static_cast<int64_t>(imm));
  }

  std::tie(execution_result_, fcsr_status) = alu::Alu::dfpexecute(ID_EX_REG.alu_operation, reg1_value, reg2_value, reg3_value, rm);
  EX_MEM_REG.alu_result = execution_result_;
  EX_MEM_REG.fcsr_status = fcsr_status;
  registers_.WriteCsr(0x003, fcsr_status);
}

void RV5SVM::MEM(){
  if(EX_MEM_REG.isEmpty){
    MEM_WB_REG.isEmpty = true;
    return;
  }
  if(MEM_WB_REG.isEmpty && !EX_MEM_REG.isEmpty){
    MEM_WB_REG.isEmpty = false;
  }

  MEM_WB_REG.alu_result = EX_MEM_REG.alu_result;
  MEM_WB_REG.rd = EX_MEM_REG.rd;
  MEM_WB_REG.mem_to_reg = EX_MEM_REG.mem_to_reg;
  MEM_WB_REG.reg_write = EX_MEM_REG.reg_write;
  MEM_WB_REG.opcode = EX_MEM_REG.opcode;
  MEM_WB_REG.funct3 = EX_MEM_REG.funct3;
  MEM_WB_REG.imm = EX_MEM_REG.imm;
  MEM_WB_REG.isFloat = false;
  MEM_WB_REG.isDouble = false;

  if(EX_MEM_REG.isFloat){
    MEM_WB_REG.isFloat = true;
    MEMF();
    return;
  }
  if(EX_MEM_REG.isDouble){
    MEM_WB_REG.isDouble = true;
    MEMD();
    return;
  }

  uint8_t opcode = EX_MEM_REG.opcode;
  uint8_t funct3 = EX_MEM_REG.funct3;

  if(EX_MEM_REG.branch){
    uint64_t pc = EX_MEM_REG.pc;
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
        UpdateProgramCounter(EX_MEM_REG.imm);
      }
    }
  }

  if(opcode == 0b1110011 && funct3 == 0b000){
    return;
  }
  // Ignoring F/D instructions for now.

  uint64_t addr = EX_MEM_REG.alu_result;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

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

    MEM_WB_REG.mem_result = memory_result_;
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

void RV5SVM::MEMF(){

  // flw instruction.
  if (EX_MEM_REG.mem_read) { // FLW
    MEM_WB_REG.alu_result = memory_controller_.ReadWord(EX_MEM_REG.alu_result);
  }

  // std::cout << "+++++ Memory result: " << memory_result_ << std::endl;

  uint64_t addr = EX_MEM_REG.alu_result;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

  // Store the float into memory, similar to integer register.
  if (EX_MEM_REG.mem_write) { // FSW
    for (size_t i = 0; i < 4; ++i) {
      old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
    uint32_t val = EX_MEM_REG.rs2_value & 0xFFFFFFFF;
    memory_controller_.WriteWord(addr, val);
    // new_bytes_vec.push_back(memory_controller_.ReadByte(addr));
    for (size_t i = 0; i < 4; ++i) {
      new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
  }

  if (old_bytes_vec!=new_bytes_vec) {
    current_delta_.memory_changes.push_back({addr, old_bytes_vec, new_bytes_vec});
  }
}

void RV5SVM::MEMD(){

  if (control_unit_.GetMemRead()) {// FLD
    MEM_WB_REG.alu_result = memory_controller_.ReadDoubleWord(EX_MEM_REG.alu_result);
  }

  uint64_t addr = EX_MEM_REG.alu_result;
  std::vector<uint8_t> old_bytes_vec;
  std::vector<uint8_t> new_bytes_vec;

  if (control_unit_.GetMemWrite()) {// FSD
    addr = execution_result_;
    for (size_t i = 0; i < 8; ++i) {
      old_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
    memory_controller_.WriteDoubleWord(addr, EX_MEM_REG.rs2_value);
    for (size_t i = 0; i < 8; ++i) {
      new_bytes_vec.push_back(memory_controller_.ReadByte(addr + i));
    }
  }

  if (old_bytes_vec!=new_bytes_vec) {
    current_delta_.memory_changes.push_back({addr, old_bytes_vec, new_bytes_vec});
  }
}

// CSR writing.
void RV5SVM::WriteBackCsr() {
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

void RV5SVM::WB(){
  if(MEM_WB_REG.isEmpty)   return;

  uint8_t opcode = MEM_WB_REG.opcode;
  uint8_t funct3 = MEM_WB_REG.funct3;
  uint8_t rd = MEM_WB_REG.rd;
  int32_t imm = MEM_WB_REG.imm;

  if(opcode == get_instr_encoding(Instruction::kecall).opcode &&
    funct3 == get_instr_encoding(Instruction::kecall).funct3) {
    return;
  }
  
  if(MEM_WB_REG.isFloat){
    WBF();
    return;
  }
  if(MEM_WB_REG.isDouble){
    WBD();
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
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }
}

void RV5SVM::WBF(){
  uint8_t opcode = MEM_WB_REG.opcode;
  uint8_t funct7 = MEM_WB_REG.funct7;
  uint8_t rd = MEM_WB_REG.rd;

  uint64_t old_reg = 0;
  unsigned int reg_index = rd;
  unsigned int reg_type = 2;
  uint64_t new_reg = 0;

  if(MEM_WB_REG.reg_write){
    switch(funct7){
      case get_instr_encoding(Instruction::kfle_s).funct7:
      case get_instr_encoding(Instruction::kfcvt_w_s).funct7:
      case get_instr_encoding(Instruction::kfmv_x_w).funct7: {
        old_reg = registers_.ReadGpr(rd);
        registers_.WriteGpr(rd, MEM_WB_REG.alu_result);
        new_reg = MEM_WB_REG.alu_result;
        reg_type = 0;
        break;
      }

      default: {
        switch(opcode){
          case get_instr_encoding(Instruction::kflw).opcode: {
            old_reg = registers_.ReadFpr(rd);
            registers_.WriteFpr(rd, MEM_WB_REG.mem_result);
            new_reg = MEM_WB_REG.mem_result;
            reg_type = 2;
            break;
          }

          default: {
            old_reg = registers_.ReadFpr(rd);
            registers_.WriteFpr(rd, MEM_WB_REG.alu_result);
            new_reg = MEM_WB_REG.alu_result;
            reg_type = 2;
            break;
          }
        }
      }
    }
  }
  if (old_reg!=new_reg) {
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }
}

void RV5SVM::WBD(){
  uint8_t opcode = MEM_WB_REG.opcode;
  uint8_t funct7 = MEM_WB_REG.funct7;
  uint8_t rd = MEM_WB_REG.rd;

  uint64_t old_reg = 0;
  unsigned int reg_index = rd;
  unsigned int reg_type = 2;
  uint64_t new_reg = 0;

  if(MEM_WB_REG.reg_write){
    if(funct7 == 0b1010001 || funct7 == 0b1100001 || funct7 == 0b1110001){
      old_reg = registers_.ReadGpr(rd);
      registers_.WriteGpr(rd, MEM_WB_REG.alu_result);
      new_reg = MEM_WB_REG.alu_result;
      reg_type = 0;
    }

    else if(opcode == 0b0000111){
      old_reg = registers_.ReadFpr(rd);
      registers_.WriteFpr(rd, MEM_WB_REG.mem_result);
      new_reg = MEM_WB_REG.mem_result;
      reg_type = 2;
    }

    else{
      old_reg = registers_.ReadFpr(rd);
      registers_.WriteFpr(rd, MEM_WB_REG.alu_result);
      new_reg = MEM_WB_REG.alu_result;
      reg_type = 2;
    }
  }

  if (old_reg!=new_reg) {
    current_delta_.register_changes.push_back({reg_index, reg_type, old_reg, new_reg});
  }
}

// RUN.
void RV5SVM::Run() {
  // Clear the stop flag, clearing the VM to run.
  ClearStop();
  // Number of instructions executed.
  uint64_t instruction_executed = 0;
  // Keep going as long as we don't want to stop or PC exceeds the max program size.
  do {
    // Check if max instructions are exceeded.
    if (stop_requested_ || instruction_executed > vm_config::config.getInstructionExecutionLimit())
      break;

    WB();
    MEM();
    EX();
    ID();
    IF();
    // Increment the insturction counters and cycles.
    instructions_retired_++;
    instruction_executed++;
    cycle_s_++;
    // Log the PC.
    std::cout << "Program Counter: " << program_counter_ << std::endl;
  } while(!(IF_ID_REG.isEmpty && ID_EX_REG.isEmpty && EX_MEM_REG.isEmpty && MEM_WB_REG.isEmpty));
  if (program_counter_ >= program_size_) {
    std::cout << "VM_PROGRAM_END" << std::endl;
    output_status_ = "VM_PROGRAM_END";
  }
  // DUmp the register and memory states.
  DumpRegisters(globals::registers_dump_file_path, registers_);
  DumpState(globals::vm_state_dump_file_path);
}

// Run with debugging.
void RV5SVM::DebugRun() {
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
      WB();
      MEM();
      EX();
      ID();
      IF();
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
void RV5SVM::Step() {
  // Store the old PC.
  current_delta_.old_pc = program_counter_;
  // Go forward if permitted.
  if (program_counter_ < program_size_) {
    // Execute for one cycle.
    WB();
    MEM();
    EX();
    ID();
    IF();
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
void RV5SVM::Undo() {
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
void RV5SVM::Redo() {
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
void RV5SVM::Reset() {
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





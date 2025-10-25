#include "assembler/assembler.h"
#include "utils.h"
#include "globals.h"
#include "vm/rvss/rvss_vm.h"
#include "config.h"

#include <iostream>
#include <thread>



int main(int argc, char *argv[]) {
  setupVmStateDirectory();

  AssembledProgram program;
  RVSSVM vm;
  try {
    program = assemble("path to .s file");
  } catch (const std::runtime_error &e) {
    std::cerr << e.what() << '\n';
    return 0;
  }

  // std::cout << "Program: " << program.filename << std::endl;

  // unsigned int count = 0;
  // for (const uint32_t &instruction : program.text_buffer) {
  //     std::cout << std::bitset<32>(instruction)
  //               << " | "
  //               << std::setw(8) << std::setfill('0') << std::hex << instruction
  //               << " | "
  //               << std::setw(0) << count
  //               << std::dec << "\n";
  //     count += 4;
  // }

  vm.LoadProgram(program);
// vm.output_status_ = "something"; // 
// vm.DumpState(globals::vm_state_dump_file_path); // to dump the state
// vm.DumpRegisters(globals::registers_dump_file_path, vm.registers_); 

// vm.DebugRun(); // run WITH breakpoints
// vm.Run(); // run WITHOUT breakpoints
// vm.Step();
// vm.Undo();
// vm.Redo();

// vm.AddBreakpoint(12, /*is_line=*/ true); // breakpoint at line
// vm.RemoveBreakpoint(12, /*is_line=*/ true); // breakpoint at line

// vm.AddBreakpoint(0x4, /*is_line=*/ false); // breakpoint at address
// vm.RemoveBreakpoint(0x4, /*is_line=*/ false); // breakpoint at address

// vm.ModifyRegister(reg_name, value); 
// vm.registers_.ReadGpr(12); 
// vm.registers_.ReadFpr(12);

// vm.memory_controller_.WriteByte(address, static_cast<uint8_t>(value));
// vm.memory_controller_.WriteHalfWord(address, static_cast<uint16_t>(value));
// vm.memory_controller_.WriteWord(address, static_cast<uint32_t>(value));
// vm.memory_controller_.WriteDoubleWord(address, value);

// vm.memory_controller_.ReadByte(address);
// vm.memory_controller_.ReadHalfWord(address);
// vm.memory_controller_.ReadWord(address);
// vm.memory_controller_.ReadDoubleWord(address);

// vm.memory_controller_.DumpMemory({address, number_of_rows}); // each row is 8 bytes 


// vm_config::config.run_step_delay = 100/*ms*/;
// vm_config::config.instruction_execution_limit = 10000; // max num instrs which can run in one vm.Run();


  return 0;
}
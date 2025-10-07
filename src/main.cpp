#include "main.h"
#include "assembler/assembler.h"
#include "utils.h"
#include "globals.h"
#include "vm/rvss/rvss_vm.h"
#include "vm_runner.h"
#include "command_handler.h"
#include "config.h"

#include <iostream>
#include <thread>
#include <bitset>
#include <regex>


// Main function, entry point.
int main(int argc, char *argv[]) {

  // No argument case.
  if (argc <= 1) {
    std::cerr << "No arguments provided. Use --help for usage information.\n";
    return 1;
  }

  // Parse the arguments.
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    // --help flag case.
    if (arg == "--help" || arg == "-h") {
        std::cout << "Usage: " << argv[0] << " [options]\n"
                  << "Options:\n"
                  << "  --help, -h           Show this help message\n"
                  << "  --assemble <file>    Assemble the specified file\n"
                  << "  --run <file>         Run the specified file\n"
                  << "  --verbose-errors     Enable verbose error printing\n"
                  << "  --start-vm           Start the VM with the default program\n"
                  << "  --start-vm --vm-as-backend  Start the VM with the default program in backend mode\n";
        return 0;

      // --assemble flag case.
    } else if (arg == "--assemble") {
        // Return an error if no file is specified.
        if (++i >= argc) {
            std::cerr << "Error: No file specified for assembly.\n";
            return 1;
        }
        try {
            // Attempt to assemble the file.
            AssembledProgram program = assemble(argv[i]);

            // Print the assembled file name.
            std::cout << "Assembled program: " << program.filename << '\n';
            return 0;

          // If an erro arises, print it and return unsuccessful execution.
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << '\n';
            return 1;
        }

      // --run flag case.
    } else if (arg == "--run") {
        // Return error if no file is specified
        if (++i >= argc) {
            std::cerr << "Error: No file specified to run.\n";
            return 1;
        }
        try {
            // Try to assemble the program.
            AssembledProgram program = assemble(argv[i]);

            // Initialise a VM for the assembled program and try to load and run ut.
            RVSSVM vm;
            vm.LoadProgram(program);
            vm.Run();

            std::cout << "Program running: " << program.filename << '\n';
            return 0;
          
          // If an error is raised, display it.
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << '\n';
            return 1;
        }
      
      // Verbose error printing flag.
    } else if (arg == "--verbose-errors") {
        globals::verbose_errors_print = true;
        std::cout << "Verbose error printing enabled.\n";
    
      // Enable VM backend mode.
    } else if (arg == "--vm-as-backend") {
        globals::vm_as_backend = true;
        std::cout << "VM backend mode enabled.\n";
      
      // Start VM.
    } else if (arg == "--start-vm") {
        break; 

      // Default case.
    } else {
        std::cerr << "Unknown option: " << arg << '\n';
        return 1;
    }
  }
  

  // Set up VM State Directory.
  setupVmStateDirectory();


  // Objects for the assembled program and VM.
  AssembledProgram program;
  RVSSVM vm;

  // idk extra code lol
  // try {
  //   program = assemble("/home/vis/Desk/codes/assembler/examples/ntest1.s");
  // } catch (const std::runtime_error &e) {
  //   std::cerr << e.what() << '\n';
  //   return 0;
  // }

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

  // vm.LoadProgram(program);
  
  // VM Started!
  std::cout << "VM_STARTED" << std::endl;
  // std::cout << globals::invokation_path << std::endl;

  // VM thread
  std::thread vm_thread;
  bool vm_running = false;

  // Lambda fuction to launch the vm thread?
  auto launch_vm_thread = [&](auto fn) {
    // Checks if an older thread exists.
    if (vm_thread.joinable()) {
      // If so, then stop that thread and start the current one.
      vm.RequestStop();   
      vm_thread.join();
    }
    // Start a new vm thread.
    vm_running = true;
    // Run the thread and set the vm_running variable to false when done.
    vm_thread = std::thread([&]() {
      fn();               
      vm_running = false;
    });
  };



  // Command buffer.
  std::string command_buffer;
  while (true) {
    // std::cout << "=> ";
    // Input a command
    std::getline(std::cin, command_buffer);
    // Parse the command.
    command_handler::Command command = command_handler::ParseCommand(command_buffer);

    // Modify the simulator settings.
    if (command.type==command_handler::CommandType::MODIFY_CONFIG) {
      // Modification commands should have atleast 3 arguments.
      if (command.args.size() != 3) {
        std::cout << "VM_MODIFY_CONFIG_ERROR" << std::endl;
        continue;
      }
      // Try executing the command.
      try {
        vm_config::config.modifyConfig(command.args[0], command.args[1], command.args[2]);
        std::cout << "VM_MODIFY_CONFIG_SUCCESS" << std::endl;
      } catch (const std::exception &e) {
        std::cout << "VM_MODIFY_CONFIG_ERROR" << std::endl;
        std::cerr << e.what() << '\n';
        continue;
      }
      continue;
    }


    // Assemble and load a program file.
    if (command.type==command_handler::CommandType::LOAD) {
      // Try to parse the command.
      try {
        program = assemble(command.args[0]);
        std::cout << "VM_PARSE_SUCCESS" << std::endl;
        vm.output_status_ = "VM_PARSE_SUCCESS";
        vm.DumpState(globals::vm_state_dump_file_path);
      } catch (const std::runtime_error &e) {
        std::cout << "VM_PARSE_ERROR" << std::endl;
        vm.output_status_ = "VM_PARSE_ERROR";
        vm.DumpState(globals::vm_state_dump_file_path);
        std::cerr << e.what() << '\n';
        continue;
      }
      vm.LoadProgram(program);
      std::cout << "Program loaded: " << command.args[0] << std::endl;

      // Start execution
    } else if (command.type==command_handler::CommandType::RUN) {
      launch_vm_thread([&]() { vm.Run(); });

      // Start execution with debug.
    } else if (command.type==command_handler::CommandType::DEBUG_RUN) {
      launch_vm_thread([&]() { vm.DebugRun(); });

      // Stop the VM.
    } else if (command.type==command_handler::CommandType::STOP) {
      vm.RequestStop();
      std::cout << "VM_STOPPED" << std::endl;
      vm.output_status_ = "VM_STOPPED";
      vm.DumpState(globals::vm_state_dump_file_path);

      // Take one step.
    } else if (command.type==command_handler::CommandType::STEP) {
      if (vm_running) continue;
      launch_vm_thread([&]() { vm.Step(); });

      // Go through state history.
    } else if (command.type==command_handler::CommandType::UNDO) {
      if (vm_running) continue;
      vm.Undo();
    } else if (command.type==command_handler::CommandType::REDO) {
      if (vm_running) continue;
      vm.Redo();

      // Reset the VM.
    } else if (command.type==command_handler::CommandType::RESET) {
      vm.Reset();

      // Exit the VM.
    } else if (command.type==command_handler::CommandType::EXIT) {
      vm.RequestStop();
      if (vm_thread.joinable()) vm_thread.join(); // ensure clean exit
      vm.output_status_ = "VM_EXITED";
      vm.DumpState(globals::vm_state_dump_file_path);
      break;

    // Add breakpoint for debugging.
    } else if (command.type==command_handler::CommandType::ADD_BREAKPOINT) {
      vm.AddBreakpoint(std::stoul(command.args[0], nullptr, 10));
    
    // Remove breakpoint.
    } else if (command.type==command_handler::CommandType::REMOVE_BREAKPOINT) {
      vm.RemoveBreakpoint(std::stoul(command.args[0], nullptr, 10));
    
    // Modify a register.
    } else if (command.type==command_handler::CommandType::MODIFY_REGISTER) {
      try {
        if (command.args.size() != 2) {
          std::cout << "VM_MODIFY_REGISTER_ERROR" << std::endl;
          continue;
        }
        std::string reg_name = command.args[0];
        uint64_t value = std::stoull(command.args[1], nullptr, 16);
        vm.ModifyRegister(reg_name, value);
        DumpRegisters(globals::registers_dump_file_path, vm.registers_);
        std::cout << "VM_MODIFY_REGISTER_SUCCESS" << std::endl;
      } catch (const std::out_of_range &e) {
        std::cout << "VM_MODIFY_REGISTER_ERROR" << std::endl;
        continue;
      } catch (const std::exception& e) {
        std::cout << "VM_MODIFY_REGISTER_ERROR" << std::endl;
        continue;
      }
    
    // Read a register.
    } else if (command.type==command_handler::CommandType::GET_REGISTER) {
      std::string reg_str = command.args[0];
      if (reg_str[0] == 'x') {
        std::cout << "VM_REGISTER_VAL_START";
        std::cout << "0x"
                  << std::hex
                  << vm.registers_.ReadGpr(std::stoi(reg_str.substr(1))) 
                  << std::dec;
        std::cout << "VM_REGISTER_VAL_END"<< std::endl;
      } 
    }

    // Modify the memory state.
    else if (command.type==command_handler::CommandType::MODIFY_MEMORY) {
      if (command.args.size() != 3) {
        std::cout << "VM_MODIFY_MEMORY_ERROR" << std::endl;
        continue;
      }
      try {
        uint64_t address = std::stoull(command.args[0], nullptr, 16);
        std::string type = command.args[1];
        uint64_t value = std::stoull(command.args[2], nullptr, 16);

        if (type == "byte") {
          vm.memory_controller_.WriteByte(address, static_cast<uint8_t>(value));
        } else if (type == "half") {
          vm.memory_controller_.WriteHalfWord(address, static_cast<uint16_t>(value));
        } else if (type == "word") {
          vm.memory_controller_.WriteWord(address, static_cast<uint32_t>(value));
        } else if (type == "double") {
          vm.memory_controller_.WriteDoubleWord(address, value);
        } else {
          std::cout << "VM_MODIFY_MEMORY_ERROR" << std::endl;
          continue;
        }
        std::cout << "VM_MODIFY_MEMORY_SUCCESS" << std::endl;
      } catch (const std::out_of_range &e) {
        std::cout << "VM_MODIFY_MEMORY_ERROR" << std::endl;
        continue;
      } catch (const std::exception& e) {
        std::cout << "VM_MODIFY_MEMORY_ERROR" << std::endl;
        continue;
      }
    }
    
    
    // Dump the memory state.
    else if (command.type==command_handler::CommandType::DUMP_MEMORY) {
      try {
        vm.memory_controller_.DumpMemory(command.args);
      } catch (const std::out_of_range &e) {
        std::cout << "VM_MEMORY_DUMP_ERROR" << std::endl;
        continue;
      } catch (const std::exception& e) {
        std::cout << "VM_MEMORY_DUMP_ERROR" << std::endl;
        continue;
      }

    // Print the current memory state.
    } else if (command.type==command_handler::CommandType::PRINT_MEMORY) {
      for (size_t i = 0; i < command.args.size(); i+=2) {
        uint64_t address = std::stoull(command.args[i], nullptr, 16);
        uint64_t rows = std::stoull(command.args[i+1]);
        vm.memory_controller_.PrintMemory(address, rows);
      }
      std::cout << std::endl;

    // Get a memory point.
    } else if (command.type==command_handler::CommandType::GET_MEMORY_POINT) {
      if (command.args.size() != 1) {
        std::cout << "VM_GET_MEMORY_POINT_ERROR" << std::endl;
        continue;
      }
      // uint64_t address = std::stoull(command.args[0], nullptr, 16);
      vm.memory_controller_.GetMemoryPoint(command.args[0]);
    } 

    // Feed the input into the simulated stdin
    else if (command.type==command_handler::CommandType::VM_STDIN) {
      vm.PushInput(command.args[0]);
    }
    
    // Cache dumping.
    else if (command.type==command_handler::CommandType::DUMP_CACHE) {
      std::cout << "Cache dumped." << std::endl;
    } else {
      std::cout << "Invalid command.";
      std::cout << command_buffer << std::endl;
    }

  }






  return 0;
}
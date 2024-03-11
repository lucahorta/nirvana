#include "hook_manager.h"

NTSTATUS __stdcall NtQuerySystemInformation_hk(
		ULONG	                 SystemInformationClass,
		PSYSTEM_PROCESSES        SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength
	) {
		// this calls the original function of whatever hook were in by stack walking.. pretty clean if you ask me
		auto r = hook_manager::call_original<NTSTATUS>(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		
		//ex you can hide chrome from taskmanager like this		
		if (r == 0 && SystemInformationClass == 5 && SystemInformation && SystemInformationLength != 0) {
			auto system_information = SystemInformation;
			while (system_information) {
				char process_name[256];
				memset(process_name, 0, sizeof(process_name));
				WideCharToMultiByte(CP_ACP, 0, system_information->ProcessName.Buffer, system_information->ProcessName.Length, process_name, sizeof(process_name), NULL, NULL);
				if (strcmp(process_name, "chrome.exe") == 0) { 
					system_information->InheritedFromProcessId = globals::explorer_pid; // change to explorer pid
				}
			}
		}
		return r;
	}

int main() {
		globals::hm.start(); // first start the hook manager		
		globals::hm.add_hook(hook_manager::get_index("NtQuerySystemInformation"), 4 * 4, NtQuerySystemInformation_hk);
		// provide the name of the import of the function you wanna hook and the number of parameter bytes lastly you just provide the pointer to the function that receives the hook
		// after you're done adding all your hooks hook heavens gate.
		globals::hm.hook_gate();
	}
}
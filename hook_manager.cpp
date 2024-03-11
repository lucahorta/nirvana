#include "hook_manager.h"

#include <io.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include "globals.h"

namespace hook_manager {
	void* orig_ptr;
	void* hook_descriptors;

	__declspec(naked) void cpy_stack() {
		__asm
		{
			pop edi
			//shl ecx, 2 //  ecx bytes to move
			mov ebx, esp //  ebx move to
			sub ebx, ecx //  edx copy from
			sub esp, ecx
			loop_label :
			cmp ecx, 0
				je return
				mov al, byte ptr[edx]
				mov byte ptr[ebx], al
				add edx, 1
				add ebx, 1
				sub ecx, 1
				jmp loop_label
				return:
			jmp edi
		}
	};

	__declspec(naked) void hg_handler() {
		__asm
		{
			mov edx, hook_descriptors
		loop_label :
			cmp word ptr [edx], ax
			je stay
			add edx, 0xC
			cmp [edx], 0
			je leave_hook
			jmp loop_label

		stay :
			mov ecx, 0xDEADBEEF
			push ecx
			xor ecx, ecx // dont want it getting pushed

			pushad
			add edx, 4
			mov ecx, [edx]
			add edx, 4
			mov esi, [edx] // use push ad stack space to store esi

			mov edx, esp
			add edx, 0x2C //  edx start of data
			call cpy_stack
			call esi

			mov ecx, esp /// do this so the pop ad replaces the eax returned by the fun
			add ecx, 0x1C
			mov[ecx], eax

			popad
			add esp, 4 // get rid off deadbeef
			ret

		leave_hook :
			jmp orig_ptr
		}
	}

	__declspec(naked) void* get_gate_ptr() {
		__asm {
			mov eax, dword ptr fs : [0xC0]
			ret
		}
	}

	int get_index(const char* name) {
		const char* mods[] = { "ntdll.dll", "win32u.dll", "user32.dll" };

		auto fn_p = (void*)nullptr;

		for (int i = 0; i < sizeof(mods) / sizeof(char*) && !fn_p; i++) {
			fn_p = GetProcAddress(LoadLibraryA(mods[i]), name);
		}

		if (!fn_p) {
			return -1;
		}

		int r = 0;
		if (*(uint8_t*)fn_p == 0xFF) { /// resolve jump
			fn_p = **(void***)((char*)fn_p + 2);
		}

		if (*(uint8_t*)fn_p == 0xB8) { /// mov eax
			memcpy(&r, (char*)fn_p + 1, 4);
		}
		else {
			return -1;
		}

		return r;
	}

	struct c_hook_manager::hook_descriptor_t {
		int index;
		int param_count;
		void* hook_handler;

		hook_descriptor_t(int index, int param_count, void* hook_handler) : index(index), param_count(param_count), hook_handler(hook_handler) {}
	};

	void c_hook_manager::start(int projected_amount) {
		hooks = (hook_descriptor_t*)malloc((projected_amount + 1) * sizeof(hook_descriptor_t));
		hook_descriptors = hooks;
		size = projected_amount * sizeof(hook_descriptor_t);
		cur_index = 0;
		memset(hooks, 0, size);
	}

	void c_hook_manager::add_hook(int index, int param_count, void* hook_handler) {
		if (index == -1) {
			MessageBoxA(0, "could not get func", 0, 0);
			return;
		}
		if ((cur_index + 3) * sizeof(hook_descriptor_t) > size) { /// + 3 because we need atleast one empty one to know when to stop the asm.
			auto temp = hooks;
			hooks = (hook_descriptor_t*)std::malloc(size + 5 * sizeof(hook_descriptor_t));
			memset(hooks, 0, size + 5 * sizeof(hook_descriptor_t));
			memcpy(hooks, temp, size);
			hook_descriptors = hooks;
			std::free(temp);
			size = size + 5 * sizeof(hook_descriptor_t);
		}
		hook_descriptor_t cur_descriptor(index, param_count, hook_handler);
		memcpy(&hooks[cur_index], &cur_descriptor, sizeof(hook_descriptor_t));
		cur_index++;
	}

	void c_hook_manager::stop() {
		free(hooks);
		unhook_gate();
	}

	void* c_hook_manager::get_buffer() {
		return (void*)hooks;
	}

	void c_hook_manager::delete_hook(int syscall_index) {
		for (int i = 0; i < cur_index; i++) {
			if (syscall_index == hooks[i].index) {
				for (int j = i + 1; j < cur_index; j++) {
					hooks[j - 1] = hooks[j];
				}
				cur_index--;
				memset(&hooks[cur_index], 0, sizeof(hook_descriptor_t));
				break;
			}
		}
	}

	void c_hook_manager::hook_gate() {
		auto gate_ptr = (uint8_t*)get_gate_ptr();

		orig_ptr = VirtualAlloc(0, 100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memset(orig_ptr, 0, 100);
		memcpy(orig_ptr, gate_ptr, 0x10);

		*(uint32_t*)((uint8_t*)orig_ptr + 1) = (uint32_t)orig_ptr + 9; // change absolute addressing to point to orig ptr

		uint8_t hook_bytes[] = { 0xFF, 0x2D, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x23, 0x00 }; // x64 jump to hook handler and switch back to x86
		*(uint32_t*)(&hook_bytes[6]) = (uint32_t)(hg_handler);

		auto hook_ptr = gate_ptr + 9;

		DWORD old_prot;
		VirtualProtect(hook_ptr, sizeof(hook_bytes), PAGE_EXECUTE_READWRITE, &old_prot);
		{
			memcpy(hook_ptr, hook_bytes, sizeof(hook_bytes));
		}
		VirtualProtect(hook_ptr, sizeof(hook_bytes), old_prot, &old_prot);
	}

	void c_hook_manager::unhook_gate() {
		auto gate_ptr = (uint8_t*)get_gate_ptr();

		DWORD old_prot;
		VirtualProtect(gate_ptr, 40, PAGE_EXECUTE_READWRITE, &old_prot);
		{
			memcpy(gate_ptr + 9, ((uint8_t*)orig_ptr + 9), 20); // 20 for instruction bounds
		}
		VirtualProtect(gate_ptr, 40, old_prot, &old_prot);
		VirtualFree(orig_ptr, 0, MEM_RELEASE);
	}
}


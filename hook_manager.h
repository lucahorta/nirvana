#pragma once
#include <windows.h>
#include <iostream>
#include <fstream>
#include <dbghelp.h>
#include <stdio.h>
#include <intrin.h>
#include <winternl.h>
#include <list>
#include <TlHelp32.h>

namespace hook_manager {
	extern void* orig_ptr;
	extern void* hook_descriptors;

	template<typename R, typename... T> extern R __cdecl call_hooked(int idx, T... t);
	template<typename R, typename... T> extern R __cdecl call_original(const T... t);
	extern void cpy_stack();
	extern void hg_handler();
	extern void* get_gate_ptr();
	extern int get_index(const char* name);

	extern class c_hook_manager {
		struct hook_descriptor_t;

		hook_descriptor_t* hooks;
		int size;

		int cur_index;
		bool spinlock_key;

		uint8_t original_bytes[8];
		uint8_t jmp_relative[5] = { 0xe9, 0x90, 0x90, 0x90, 0x90 };

	public:
		void start(int projected_amount = 10);
		void add_hook(int index, int param_count, void* hook_handler);
		void stop();
		void* get_buffer();
		void delete_hook(int syscall_index);
		void hook_gate();
		void unhook_gate();
	};

	template<typename R, typename... T>
	__declspec(naked) R __cdecl call_hooked(int idx, T... t) /// detemplate this 
	{
		//return call_hooked_impl<R, T...>(idx, sizeof...(T), t...);
		__asm {
			mov edx, esp
			add edx, 4
			mov eax, [edx] // get idx
			mov ecx, [esp] // ret addy
			mov[edx], ecx
			mov esp, edx
			push back
			jmp orig_ptr
			back :
			pop ecx
				sub esp, 4
				push ecx
				ret
		}
	}

	template<typename R, typename... T>
	__declspec(naked) R __cdecl call_original(const T... t)
	{
		__asm { /// stack walk
			//push esi
			//push edi
			//push ebx

			mov ecx, esp
			mov edx, 0xDEADBEEF

			loop_label:
			cmp	edx, [ecx]
				je found_frame
				add ecx, 4
				jmp loop_label

				found_frame : ///Restore some shit only eax necessary but why tf not.
			sub ecx, 0x4
				mov eax, [ecx]
				sub ecx, 4

				///we can use this place in pushad to save stuff since ecx and edx are mutable.
				//mov edx, [esp]
				//mov [ecx], edx // saving the return address
				sub ecx, 8

				mov ebx, [ecx]
				sub ecx, 12
				mov esi, [ecx]
				sub ecx, 0x4
				mov edi, [ecx]

				//pop ecx
				push back
				//push ebx /// doesnt matter
				jmp orig_ptr

				back :
			///pop ecx
			//int 3
			//add esp, 0x4
			///mov ecx, esp
			///mov edx, 0xDEADBEEF
			///loop_label2:
			///cmp	edx, [ecx]
			///je found_frame2
			///add ecx, 4
			///jmp loop_label2
			///
			///found_frame2:
			///sub ecx, 0x4
			//mov [ecx], eax 
			///sub ecx, 0x4
			///mov edx, [ecx]
			///push edx
			ret
		}
		//using original_t = R(__cdecl*)(T...);
		//((original_t)orig_ptr)(t...);
	}
}




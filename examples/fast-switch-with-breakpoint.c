/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

//Includes for fast switch example
#include <libvmi/slat.h>
#include <xenctrl.h>

#define PAGE_RANGE 12
#define PAGE_SIZE 4096

// Use fast switch breakpoint if not defined
//#define USE_CR3_GUARD

static unsigned char BREAKPOINT = 0xcc;
static vmi_event_t int_event;
static vmi_event_t cr3_event = {0};
static vmi_event_t sstep_event = {0};
static vmi_event_t mem_event = {0};

struct process_return
{
    addr_t eprocess_base;
    pid_t pid;
    addr_t dtb;
};
typedef struct process_return *process_return_t;

struct interrupt_data
{
    addr_t sym_vaddr;
    addr_t sym_pa;
    unsigned char saved_opcode;
    uint64_t hit_count;
    uint64_t hit_count_wrong_cr3;
    addr_t targetCr3;
};
typedef struct interrupt_data *interrupt_data_t;

struct cr3event_data
{
    addr_t interrupt_PA;
    unsigned char saved_opcode;
    addr_t targetCr3;
};
typedef struct cr3event_data *cr3event_data_t;

struct ShadowPage
{
    addr_t read_write, execute;
    uint16_t vcpu;
};
static struct ShadowPage shadow_page;

event_response_t breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!event->data)
    {
        fprintf(stderr, "Empty event data in breakpoint callback !\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    // get back callback data struct
    interrupt_data_t cb_data = (interrupt_data_t) event->data;

    if (!event->interrupt_event.insn_length)
    {
        event->interrupt_event.insn_length = 1;
    }

    if (event->x86_regs->rip != cb_data->sym_vaddr)
    {
        // not our breakpoint
        event->interrupt_event.reinject = 1;
        printf("Not our breakpoint. Reinjecting INT3\n");
        return VMI_EVENT_RESPONSE_NONE;
    } else
    {
        if (event->x86_regs->cr3 == cb_data->targetCr3)
        {
            cb_data->hit_count++;
        } else
        {
            cb_data->hit_count_wrong_cr3++;
        }
        event->interrupt_event.reinject = 0;

        // write saved opcode
        if (VMI_FAILURE ==
            vmi_write_pa(vmi, cb_data->sym_pa, sizeof(cb_data->saved_opcode), &cb_data->saved_opcode, NULL))
        {
            printf("Failed to write back original opcode at 0x%" PRIx64 "\n", cb_data->sym_pa);
            return VMI_EVENT_RESPONSE_NONE;
        }
        // enable singlestep
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }
}

event_response_t fastswitch_breakpoint_cb(__attribute__((unused)) vmi_instance_t vmi, vmi_event_t *event)
{
    if (!event->data)
    {
        fprintf(stderr, "Empty event data in breakpoint callback !\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    // get back callback data struct
    interrupt_data_t cb_data = (interrupt_data_t) event->data;

    if (!event->interrupt_event.insn_length)
        event->interrupt_event.insn_length = 1;

    if (event->x86_regs->rip != cb_data->sym_vaddr)
    {
        // not our breakpoint
        event->interrupt_event.reinject = 1;
        printf("Not our breakpoint. Reinjecting INT3\n");
        return VMI_EVENT_RESPONSE_NONE;
    } else
    {
        if (event->x86_regs->cr3 == cb_data->targetCr3)
        {
            cb_data->hit_count++;
        } else
        {
            cb_data->hit_count_wrong_cr3++;
        }
        event->interrupt_event.reinject = 0;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t single_step_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!event->data)
    {
        printf("Empty event data in singlestep callback !\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // get back callback data struct
    struct interrupt_data *cb_data = (struct interrupt_data *) event->data;

    // restore breakpoint
    if (VMI_FAILURE == vmi_write_pa(vmi, cb_data->sym_pa, sizeof(BREAKPOINT), &BREAKPOINT, NULL))
    {
        printf("Failed to write breakpoint at 0x%" PRIx64 "\n", cb_data->sym_pa);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // disable singlestep
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

void restore_original_value(vmi_instance_t vmi, addr_t interrupt_PA, unsigned char saved_opcode)
{

    if (VMI_FAILURE == vmi_write_8_pa(vmi, interrupt_PA, &saved_opcode))
    {
        printf("Failed to write original value %"PRIx8" to PA %"PRIx64"\n", saved_opcode, interrupt_PA);
    }
}

void set_interrupt_event(vmi_instance_t vmi, addr_t interrupt_PA)
{
    if (VMI_FAILURE == vmi_write_pa(vmi, interrupt_PA, sizeof(BREAKPOINT), &BREAKPOINT, NULL))
    {
        printf("Failed to write interrupt value %"PRIx8" to PA %"PRIx64"\n", BREAKPOINT, interrupt_PA);
    }
}

event_response_t cr3_callback_overwriting_interrupt_event(vmi_instance_t vmi, vmi_event_t *event)
{
    cr3event_data_t cb_data = (cr3event_data_t) event->data;
    if (event->reg_event.value == cb_data->targetCr3)
    {
        set_interrupt_event(vmi, cb_data->interrupt_PA);
    } else
    {
        restore_original_value(vmi, cb_data->interrupt_PA, cb_data->saved_opcode);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t
fake_handle_mem_event(__attribute__((unused)) vmi_instance_t vmi, __attribute__((unused)) vmi_event_t *event)
{
    return VMI_EVENT_RESPONSE_NONE;
}

int setup_fast_switch(xc_interface *xc, vmi_instance_t vmi, uint64_t vm_id, uint targetCr3, uint16_t view_rw, uint16_t view_x)
{
    for (uint i = 0; i < vmi_get_num_vcpus(vmi); i++)
    {
        printf("Setting fast switch for vcpu %d\n", i);
        errno = 0;
        int rc = xc_altp2m_add_fast_switch(xc, vm_id, i, targetCr3, view_rw, view_x);
        if (rc < 0)
        {
            int last_error = errno;
            printf("add fast switch failed: %d\n", rc);
            printf("xenctrl last error code: %d\n", last_error);
            printf("xenctrl error message: %s\n", strerror(last_error));
            return 1;
        }
    }

    return 0;
}

int altp2m_setup(xc_interface *xc, vmi_instance_t vmi, uint16_t *view_rw, uint16_t *view_x)
{
    uint64_t vm_id = vmi_get_vmid(vmi);
    if (vm_id == VMI_INVALID_DOMID)
    {
        printf("Unable to fetch vm id.\n");
        return 1;
    }
    // grab current value of ALTP2M.
    uint64_t current_altp2m;
    if (xc_hvm_param_get(xc, vm_id, HVM_PARAM_ALTP2M, &current_altp2m) < 0)
    {
        printf("Failed to get HVM_PARAM_ALTP2M.\n");
        return 1;
    } else
    {
        printf("current_altp2m = %lu\n", current_altp2m);
    }
    // is ALTP2M not at external mode? turn it on.
    if (current_altp2m != XEN_ALTP2M_external &&
        xc_hvm_param_set(xc, vm_id, HVM_PARAM_ALTP2M, XEN_ALTP2M_external) < 0)
    {
        printf("Failed to set HVM_PARAM_ALTP2M.\n");
        return 1;
    }

    //create second slat for fast switch
    if (VMI_FAILURE == vmi_slat_set_domain_state(vmi, true))
    {
        printf("Could not enable slat. Aborting");
        return 1;
    }

    if (VMI_FAILURE == vmi_slat_create(vmi, view_rw))
    {
        printf("Could not create view_rw. Aborting\n");
        return 1;
    }
    printf("view_rw is %d\n", *view_rw);

    if (VMI_FAILURE == vmi_slat_create(vmi, view_x))
    {
        printf("Could not create view_x. Aborting\n");
        return 1;
    }
    printf("view_x is %d\n", *view_x);

    return 0;
}

int get_suitable_process_information(vmi_instance_t vmi, char *target_process_name, process_return_t target_process)
{
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset))
        return 1;
    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset))
        return 1;
    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset))
        return 1;

    printf("tasks_offset %lu\n", tasks_offset);
    printf("tasks_offset %lu\n", name_offset);
    printf("tasks_offset %lu\n", pid_offset);

    // find PEPROCESS PsInitialSystemProcess
    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head))
    {
        printf("Failed to find PsActiveProcessHead\n");
        return 1;
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry))
    {
        printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        return 1;
    }

    /* walk the task list */
    bool found_suitable_process = false;
    while (!found_suitable_process)
    {
        current_process = cur_list_entry - tasks_offset;

        /* Note: the task_struct that we are looking at has a lot of
         * information.  However, the process name and id are burried
         * nice and deep.  Instead of doing something sane like mapping
         * this data to a task_struct, I'm just jumping to the location
         * with the info that I want.  This helps to make the example
         * code cleaner, if not more fragile.  In a real app, you'd
         * want to do this a little more robust :-)  See
         * include/linux/sched.h for mode details */

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t *) &pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname)
        {
            printf("Failed to find procname\n");
            return 1;
        }

        /* print out the process name */
        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        if (!strcmp(procname, target_process_name))
        {
            printf("found %s\n", target_process_name);

            printf("Getting dtb\n");
            addr_t dtb;
            // get system cr3
            if (vmi_pid_to_dtb(vmi, pid, &dtb) == VMI_FAILURE)
            {
                printf("Could not get CR3, Aborting");
                free(procname);
                procname = NULL;
                break;
            }
            printf("Got dtb: 0x%x\n", (uint) dtb);
            found_suitable_process = true;
            target_process->eprocess_base = current_process;
            target_process->pid = pid;
            target_process->dtb = dtb;
        }
        free(procname);
        procname = NULL;

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        status_t status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            return 1;
        }

        if (next_list_entry == list_head)
        {
            break;
        }
    }

    return 0;
}

addr_t get_dll_base_address(vmi_instance_t vmi, struct process_return suitable_process, const char *target_dll)
{
    addr_t dll_base_address = 0;
    addr_t module_list_base = 0;

    addr_t peb = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, suitable_process.eprocess_base + 0x1b0, 0, &peb))
    {
        printf("Failed to read PEB pointer from %"PRIx64"\n", suitable_process.eprocess_base + 0x1b0);
        goto error_exit;
    }
    printf("PEB pointer %"PRIx64"\n", peb);


    addr_t ldr_pointer = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, peb + 0xc, suitable_process.pid, &ldr_pointer))
    {
        printf("Failed to read LDR pointer from %"PRIx64"\n", peb + 0xc);
        goto error_exit;
    }
    printf("LDR pointer %"PRIx64"\n", ldr_pointer);

    module_list_base = ldr_pointer + 0xc;

    addr_t next_module = module_list_base;
    bool dll_found = false;
    /* walk the module list */
    while (!dll_found)
    {
        /* follow the next pointer */
        addr_t tmp_next = 0;

        vmi_read_addr_va(vmi, next_module, suitable_process.pid, &tmp_next);

        /* if we are back at the list head, we are done */
        if (module_list_base == tmp_next)
        {
            break;
        }

        addr_t ldr_data_table_entry = 0;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, tmp_next, suitable_process.pid, &ldr_data_table_entry))
        {
            printf("Failed to read LDR_DATA_TABLE_ENTRY from %"PRIx64"\n", tmp_next);
            goto error_exit;
        }
        printf("LDR_DATA_TABLE_ENTRY %"PRIx64"\n", ldr_data_table_entry);

        unicode_string_t *us = NULL;

        /*
         * The offset 0x58 and 0x2c is the offset in the _LDR_DATA_TABLE_ENTRY structure
         * to the BaseDllName member.
         * These offset values are stable (at least) between XP and Windows 7.
         */

        if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0))
        {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x58, suitable_process.pid);
        } else
        {
            us = vmi_read_unicode_str_va(vmi, ldr_data_table_entry + 0x2c, suitable_process.pid);
        }

        unicode_string_t out = {0};
        //         both of these work
        if (us &&
            VMI_SUCCESS == vmi_convert_str_encoding(us, &out,
                                                    "UTF-8"))
        {
            printf("%s\n", out.contents);
            if (!strcmp((const char *) out.contents, target_dll))
            {
                printf("found %s\n", target_dll);
                if (VMI_FAILURE ==
                    vmi_read_addr_va(vmi, ldr_data_table_entry + 0x18, suitable_process.pid, &dll_base_address))
                {
                    printf("Failed to read dll_base_address from %"PRIx64"\n", ldr_data_table_entry + 0x18);
                    goto error_exit;
                }
                printf("%s base_address %"PRIx64"\n", target_dll, dll_base_address);
                dll_found = true;
            }
            free(out.contents);
        }
        if (us)
        {
            vmi_free_unicode_str(us);
        }
        next_module = tmp_next;
    }
    error_exit:
    return dll_base_address;
}

addr_t get_function_va(vmi_instance_t vmi, addr_t process_cr3, addr_t dll_base_address, const char *function_name)
{
    addr_t function_va = 0;
    access_context_t ctx =
            {
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = process_cr3,
                    .addr = dll_base_address
            };
    if (VMI_FAILURE == vmi_translate_sym2v(vmi, &ctx, function_name, &function_va))
    {
        printf("Failed to get %s from process %"PRIx64" with dll_base_address %"PRIx64"\n", function_name, process_cr3,
               dll_base_address);
        goto error_exit;
    }

    printf("Address for %s: %"PRIx64"\n", function_name, function_va);

    error_exit:
    return function_va;
}

uint64_t allocate_page(xc_interface *xc, vmi_instance_t vmi, uint64_t vm_id)
{
    addr_t max_gfn;
    xc_domain_maximum_gpfn(xc, vm_id, &max_gfn);
    addr_t new_page = ++max_gfn;
    if (xc_domain_populate_physmap_exact(xc, vm_id, 1, 0, 0, &new_page) < 0)
    {
        printf("unable to create a new page\n");
    }

    // refresh the cached end of physical memory.
    vmi_get_max_physical_address(vmi);

    return new_page;
}

int setup_interrupt_event(vmi_instance_t vmi, interrupt_data_t interrupt_struct, event_callback_t callback)
{
    SETUP_INTERRUPT_EVENT(&int_event, callback);
    int_event.data = (void *) interrupt_struct;

    printf("Register interrupt event\n");
    return vmi_register_event(vmi, &int_event);
}

int init_libvmi(int argc, char *const *argv, vmi_instance_t *vmi)
{
    vmi_init_data_t init_data = {0};
    vmi_mode_t mode;/* this is the VM or file that we are looking at */
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return 1;
    }

    char *name = argv[1];

    if (argc == 3)
    {
        char *path = argv[2];

        // fill init_data
        init_data.count = 1;
        init_data.entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data.entry[0].data = strdup(path);
    }

    if (VMI_FAILURE ==
        vmi_get_access_mode(NULL, (void *) name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, &init_data, &mode))
    {
        fprintf(stderr, "Failed to get access mode\n");
        return 1;
    }

    /* initialize the libvmi library */
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *config = NULL;
    if (VMI_FAILURE ==
        vmi_init_complete(vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, &init_data, config_type, config, NULL))
    {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }
    return 0;
}

int setup_cr3_guarded_bp(vmi_instance_t vmi, interrupt_data_t interrupt_struct, cr3event_data_t cr3event_struct)
{
    // Init CR3 Event
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_callback_overwriting_interrupt_event;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.data = (void *) cr3event_struct;

    if (VMI_FAILURE == vmi_register_event(vmi, &cr3_event))
    {
        printf("Failed to init cr3 event\n");
        return 1;
    }

    if (VMI_FAILURE == setup_interrupt_event(vmi, interrupt_struct, breakpoint_cb))
    {
        fprintf(stderr, "Failed to register interrupt event\n");
        return 1;
    }

    // get number of vcpus
    unsigned int num_vcpus = vmi_get_num_vcpus(vmi);

    // register singlestep event
    // disabled by default
    sstep_event.version = VMI_EVENTS_VERSION;
    sstep_event.type = VMI_EVENT_SINGLESTEP;
    sstep_event.callback = single_step_cb;
    sstep_event.ss_event.enable = false;
    // allow singlestep on all VCPUs
    for (unsigned int vcpu = 0; vcpu < num_vcpus; vcpu++)
        SET_VCPU_SINGLESTEP(sstep_event.ss_event, vcpu);
    // pass struct bp_cb_data
    sstep_event.data = (void *) interrupt_struct;

    printf("Register singlestep event\n");
    if (VMI_FAILURE == vmi_register_event(vmi, &sstep_event))
    {
        fprintf(stderr, "Failed to register singlestep event\n");
        return 1;
    }
    return 0;
}

int setup_fastswitch_bp(xc_interface *xc, vmi_instance_t vmi, interrupt_data_t interrupt_struct, uint16_t *view_rw, uint16_t *view_x)
{
    uint64_t vm_id = vmi_get_vmid(vmi);
    if (vm_id == VMI_INVALID_DOMID)
    {
        printf("Unable to fetch vm id.\n");
        return 1;
    }

    if (VMI_FAILURE == setup_interrupt_event(vmi, interrupt_struct, fastswitch_breakpoint_cb))
    {
        fprintf(stderr, "Failed to register interrupt event\n");
        return 1;
    }

    if (altp2m_setup(xc, vmi, view_rw, view_x))
    {
        return 1;
    }

    if (setup_fast_switch(xc, vmi, vm_id, interrupt_struct->targetCr3, *view_rw, *view_x))
    {
        printf("Could not setup fast switch\n");
        return 1;
    }

    //init shadowpage
    shadow_page.read_write = interrupt_struct->sym_pa >> PAGE_RANGE;
    shadow_page.execute = allocate_page(xc, vmi, vm_id);

    // copy over page contents to shadow page.
    uint8_t buffer[PAGE_SIZE];
    if (vmi_read_pa(vmi, shadow_page.read_write << PAGE_RANGE, PAGE_SIZE, &buffer, NULL) != VMI_SUCCESS)
    {
        printf("Could not read origin page\n");
        return 1;
    }
    if (vmi_write_pa(vmi, shadow_page.execute << PAGE_RANGE, PAGE_SIZE, &buffer, NULL) != VMI_SUCCESS)
    {
        printf("Could not write origin page to shadow page\n");
        return 1;
    }

    if (vmi_slat_change_gfn(vmi, *view_x, shadow_page.read_write, shadow_page.execute) != VMI_SUCCESS)
    {
        printf("Could not vmi_slat_change_gfn\n");
        return 1;
    }

    // we need to register the memory event even on coordinated injection,
    // because vmi_set_mem_event has a sanity check that prevents us from setting
    // the EPT permissions if there is no suitable handler, however,
    // in the coordinated case, the actual handler is never invoked.
    SETUP_MEM_EVENT(&mem_event, ~0ull, VMI_MEMACCESS_RWX, fake_handle_mem_event, true);
    if (vmi_register_event(vmi, &mem_event) != VMI_SUCCESS)
    {
        printf("Unable to register mem event\n");
        return 1;
    }

    if (vmi_set_mem_event(vmi, shadow_page.execute, VMI_MEMACCESS_RW, *view_x) != VMI_SUCCESS)
    {
        printf("Could not set RW events on  0x%"PRIx64" in view_x %i\n", shadow_page.execute, *view_x);
        return 1;
    }

    if (vmi_set_mem_event(vmi, shadow_page.read_write, VMI_MEMACCESS_RW, *view_x) != VMI_SUCCESS)
    {
        printf("Could not set RW events on  0x%"PRIx64" in view_x %i\n", shadow_page.read_write, *view_x);
        return 1;
    }

    if (vmi_set_mem_event(vmi, shadow_page.read_write, VMI_MEMACCESS_X, *view_rw) != VMI_SUCCESS
        || vmi_set_mem_event(vmi, shadow_page.execute, VMI_MEMACCESS_X, *view_rw) != VMI_SUCCESS)
    {
        printf("Could not set X events in view_rw %i\n", *view_rw);
        return 1;
    }

    //apply patch
    addr_t offset_in_page = interrupt_struct->sym_pa & (PAGE_SIZE - 1);
    addr_t patch_location = (shadow_page.execute << PAGE_RANGE) + offset_in_page;

    // finally, we can make our changes to our shadow page.
    if (VMI_FAILURE == vmi_write_pa(vmi, patch_location, sizeof(BREAKPOINT), &BREAKPOINT, NULL))
    {
        printf("Failed to write interrupt value %"PRIx8" to PA %"PRIx64"\n", BREAKPOINT, patch_location);
        return 1;
    }
    printf("########### fast switch successfully enabled ########### \n");
    return 0;
}

int main(int argc, char **argv)
{
    int retcode;
    vmi_instance_t vmi = NULL;
    addr_t interrupt_PA = 0;
    addr_t targetCr3 = 0;
    uint16_t view_x = 0;
    uint16_t view_rw = 0;

    if (init_libvmi(argc, argv, &vmi))
    {
        return 1;
    }

    xc_interface *xc = NULL;
    xc = xc_interface_open(0, 0, 0);
    if (xc == NULL)
    {
        printf("Could not get xen interface. Aborting");
        goto error_exit;
    }

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS)
    {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    /* find target process */
    struct process_return suitable_process;
    if (get_suitable_process_information(vmi, "APIHammering2.e", &suitable_process))
    {
        goto error_exit;
    }
    targetCr3 = suitable_process.dtb;

    // find suitable address for inserting a breakpoint
    addr_t function_va = get_function_va(vmi, suitable_process.dtb,
                                         get_dll_base_address(vmi, suitable_process, "kernel32.dll"),
                                         "GetCurrentProcessId");

    unsigned char saved_opcode;
    if (VMI_FAILURE == vmi_translate_uv2p(vmi, function_va, suitable_process.pid, &interrupt_PA))
    {
        fprintf(stderr, "Could not convert VA %"PRIx64" for PID %u\n", function_va, suitable_process.pid);
        goto error_exit;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi, function_va, suitable_process.pid, &saved_opcode))
    {
        fprintf(stderr, "Failed to read opcode\n");
        goto error_exit;
    }

    struct interrupt_data interrupt_struct = {0};
    interrupt_struct.saved_opcode = saved_opcode;
    interrupt_struct.sym_vaddr = function_va;
    interrupt_struct.sym_pa = interrupt_PA;
    interrupt_struct.targetCr3 = targetCr3;

#ifdef USE_CR3_GUARD
    struct cr3event_data cr3event_struct = {0};
    cr3event_struct.interrupt_PA = interrupt_PA;
    cr3event_struct.saved_opcode = saved_opcode;
    cr3event_struct.targetCr3 = targetCr3;

    if (setup_cr3_guarded_bp(vmi, &interrupt_struct, &cr3event_struct))
    {
        goto error_exit;
    }
#else
    if (setup_fastswitch_bp(xc, vmi, &interrupt_struct, &view_rw, &view_x))
    {
        goto error_exit;
    }
#endif

    if (vmi_resume_vm(vmi) == VMI_FAILURE)
    {
        goto error_exit;
    }

    printf("Init done, waiting for events\n");

    time_t start_time, end_time;
    time(&start_time);
    time(&end_time);
    while (difftime(end_time, start_time) < 30)
    {
        time(&end_time);
        if (vmi_events_listen(vmi, 500) == VMI_FAILURE)
        {
            printf("Failed to listen on events\n");
            break;
        }
    }

    printf("Ending run after %fs\n", difftime(end_time, start_time));
    printf("Target breakpoint hit. Count: %"PRIu64"\n", interrupt_struct.hit_count);
    printf("Wrong CR3 breakpoint hit. Count: %"PRIu64"\n", interrupt_struct.hit_count_wrong_cr3);

    retcode = 0;

    error_exit:
    vmi_pause_vm(vmi);
    while (vmi_are_events_pending(vmi))
    {
        printf("Pop remaining event");
        vmi_events_listen(vmi, 10);
    }

    if (interrupt_PA && saved_opcode)
    {
        restore_original_value(vmi, interrupt_PA, saved_opcode);
    }
    vmi_clear_event(vmi, &int_event, NULL);
    vmi_stop_single_step_vcpu(vmi, &sstep_event, 0);
    vmi_clear_event(vmi, &sstep_event, NULL);
#ifdef USE_CR3_GUARD
    vmi_clear_event(vmi, &cr3_event, NULL);
#else
    if (xc != NULL && targetCr3 != 0)
    {
        for (uint i = 0; i < vmi_get_num_vcpus(vmi); i++)
        {
            xc_altp2m_remove_fast_switch(xc, vmi_get_vmid(vmi), i, targetCr3);
        }

        if (interrupt_PA != 0)
        {
            // destroy shadow page
            xc_domain_decrease_reservation_exact(xc, vmi_get_vmid(vmi), 1, 0, &interrupt_PA);
        }
    }


    vmi_slat_switch(vmi, 0);
    vmi_slat_destroy(vmi, view_rw);
    vmi_slat_destroy(vmi, view_x);

    vmi_clear_event(vmi, &mem_event, NULL);
#endif

    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if (xc != NULL)
    {
        xc_interface_close(xc);
    }

    return retcode;
}

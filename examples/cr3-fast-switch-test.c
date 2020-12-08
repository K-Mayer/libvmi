/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
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
#include <signal.h>
#include <time.h> 
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

//Includes for fast switch example
#include <libvmi/slat.h>
#include <xenctrl.h>

static int systemCr3Events = 0;
static int unwantedC3Events = 0;
static addr_t targetCr3;
static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    if(event->reg_event.value == targetCr3)
    {
        systemCr3Events++;
    }
    else
    {
        unwantedC3Events++;
    }
    
    return VMI_EVENT_RESPONSE_NONE;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    status_t status = VMI_FAILURE;
    vmi_mode_t mode = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;

    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return retcode;
    }

    char *name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    // if (VMI_FAILURE ==
    //         vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
    //     fprintf(stderr, "Failed to init LibVMI library.\n");
    //     goto error_exit;
    // }

    /* initialize the libvmi library */
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *config = NULL;
    if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, config_type, config, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    xc_interface* xc = xc_interface_open(0, 0, 0);
    if(xc == NULL)
    {
        printf("Could not get xen interface. Aborting");
        goto error_exit;
    }

    struct sigaction act;
    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* pause the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    vmi_event_t cr3_event = {0};
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.callback = cr3_callback;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;

    printf("Getting cr3\n");
    // get system cr3
    if (vmi_pid_to_dtb(vmi, 0x4, &targetCr3) == VMI_FAILURE)
    {
        printf("Could not get CR3, Aborting");
        goto error_exit;
    }
    printf("Got targetCr3: 0x%x\n", (uint)targetCr3);
    
    //get domain state
    bool isEnabled = false;
    if( VMI_FAILURE == vmi_slat_get_domain_state(vmi, &isEnabled))
    {
        printf("Could not get domain state");
        goto error_exit;
    }
    printf("Current domain state is %b", isEnabled);


    //create second slat for fast switch
    if( VMI_FAILURE == vmi_slat_set_domain_state(vmi, true))
    {
        printf("Could not enable slat. Aborting");
        goto error_exit;
    }

    int second_slat_id; 
    if( VMI_FAILURE == vmi_slat_create(vmi, &second_slat_id))
    {
        printf("Could not create second slat. Aborting");
        goto error_exit;
    }

    // register event
    if (vmi_register_event(vmi, &cr3_event) == VMI_FAILURE)
        goto error_exit;

    if (vmi_resume_vm(vmi) ==  VMI_FAILURE)
        goto error_exit;


    clock_t start_time = clock();
    int target_seconds = 120;
    int milli_seconds = 1000 * target_seconds; 
    printf("Waiting for events...\n");
    while (!interrupted && (clock() < start_time + milli_seconds)) {
        status = vmi_events_listen(vmi, 500);
        if (status == VMI_FAILURE)
            printf("Failed to listen on events\n");
    }
    printf ("Got %d cr3 events for %x in %d sec. %d other events.\n",systemCr3Events, (uint)targetCr3, target_seconds, unwantedC3Events );
    retcode = 0;
error_exit:
    vmi_clear_event(vmi, &cr3_event, NULL);

    // close xen access handle if open.
    if(xc != NULL)
    {
        xc_interface_close(xc);
    }

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}

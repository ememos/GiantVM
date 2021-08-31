## Base

### Page table
Responsible for converting VA to PA. The address of VA is composed of the page number and the offset within the page. When converting, first read the starting address of the page table from the base address register (CR3) of the page table, and then add the page number to get the page table entry of the corresponding page. Take the physical address of the page from it and add the offset to get the PA.

With the expansion of the addressing range (64-bit CPU supports 48-bit virtual address addressing space and 52-bit physical address addressing space), page tables need to occupy more and more contiguous memory space, plus each Processes must have their own page tables, and the system needs to consume a lot of memory just to maintain the page tables. To this end, a multi-level page table is introduced by taking advantage of the localized characteristics of the memory used by the program.

The current version of Linux uses four-level page tables:

Page Map Level 4(PML4) => Page Directory Pointer Table(PDPT) => Page Directory(PD) => Page Table(PT)

It is called in some places: Page Global Directory(PGD) => Page Upper Directory(PUD) => Page Middle Directory(PMD) => Page Table(PT)

Under x86_64, the size of an ordinary page is 4KB. Since the address is 64bit, a page table entry occupies 8 Bytes, so a page table can only store 512 entries. Therefore, each level of page table index uses 9 bits, and the page index (offset) uses 12 bits, so only 0-47 bits in a 64-bit address are used.

In 64-bit, EPT uses the same structure as the traditional page table, so if you do not consider TLB, a GVA to HVA needs to go through 4 * 4 times (considering the situation that access to each level of page is faulty) page table query.

The memory is accessed as many times as there are queries, and continuous access to the memory during the walk will undoubtedly affect performance. To this end, TLB(Translation Lookaside Buffer) is introduced to cache commonly used PTEs. In this way, in the case of a TLB hit, there is no need to search the memory. Utilizing the localized characteristics of the memory used by the program, the hit rate of TLB is often very high, which improves the access speed under the multi-level page table.


### Memory virtualization
QEMU uses the mmap system call to apply for a continuous size of space in the virtual address space of the process as the guest's physical memory.

Under this architecture, there are four levels of mapping for memory address access:

GVA - GPA - HVA - HPA

The GVA-GPA mapping is maintained by the guest OS, and the HVA-HPA is maintained by the host OS. So we need a mechanism to maintain the GPA-HVA mapping. Commonly used implementations are SPT(Shadow Page Table) and EPT/NPT. The former maintains the shadow page table through software, and the latter implements secondary mapping through hardware features.


### Shadow page table
KVM realizes direct mapping by maintaining the page table SPT from GVA to HPA. Then the page table can be used by physical MMU addressing. How to achieve it:

KVM sets the page table of the Guest OS to read-only. When the Guest OS makes changes, it will trigger a page fault, VMEXIT to KVM. KVM will check the access authority of the page table entry corresponding to the GVA, and judge based on the error code:

1. If it is caused by the Guest OS, the exception is injected back. Guest OS calls its own page fault processing function (apply for a page and fill the GPA of the page into the upper-level page table entry)
2. If it is caused by the inconsistency between the page table of the Guest OS and the SPT, synchronize the SPT, find the mapping relationship between GVA to GPA and then to HVA according to the Guest OS page table and mmap mapping, and then add/update GVA-HPA entries in the SPT

When the Guest OS switches the process, it loads the base address of the page table of the process to be switched into CR3 of the Guest, causing VM EXIT to return to KVM. KVM finds the corresponding SPT through the hash table, and then loads it into the machine's CR3.

Disadvantages: It is necessary to maintain an SPT for each process, which brings additional memory overhead. Need to keep the guest OS page table and SPT synchronized. Whenever a guest page fault occurs, even if it is caused by the guest's own page fault, it will cause VMExit, which is expensive.


### EPT / NPT
Intel EPT technology introduces the concepts of EPT(Extended Page Table) and EPTP(EPT base pointer). The mapping from GPA to HPA is maintained in the EPT, and the EPT base pointer is responsible for pointing to the EPT. When the Guest OS is running, the EPT address corresponding to the VM is loaded into EPTP, and the base address of the currently running process page table of the Guest OS is loaded into CR3, so when the address conversion is performed, the GVA is first realized through the page table pointed to by CR3. The conversion of GPA, and then the conversion from GPA to HPA is realized through the EPT pointed to by EPTP.

When an EPT page fault occurs, VMExit is required to KVM to update the EPT.

AMD NPT(Nested Page Table) is a solution developed by AMD. Its principle is similar to EPT, but the description and implementation are slightly different. Both Guest OS and Host have their own CR3. When the address is converted, the page table pointed to by gCR3 is from GVA to GPA, and then the page table pointed to by nCR3 is from GPA to HPA.

Advantages: The guest's page faults are handled in the guest, and the vm exit will not be performed. The address conversion is basically done by the hardware (MMU) looking up the page table.

Disadvantages: The two-level page table query can only be expected to be hit by the TLB.



## Accomplishment

### QEMU

#### Memory device simulation

##### PCDIMMDevice

```c
typedef struct PCDIMMDevice {
    /* private */
    DeviceState parent_obj;

    /* public */
    uint64_t addr;                   // The starting GPA mapped to
    uint32_t node;                   // The numa node mapped to
    int32_t slot;                    // The number of the inserted memory slot, the default is -1, which means that the
    HostMemoryBackend *hostmem;      // Corresponding backend
} PCDIMMDevice;
```

A virtual memory bank defined by QOM(qemu object model). It can be managed through QMP or QEMU command line. By adding/removing this object, the memory in the VM can be hot-plugged.


##### HostMemoryBackend

```c
struct HostMemoryBackend {
    /* private */
    Object parent;

    /* protected */
    uint64_t size;           // Provide memory size
    bool merge, dump;
    bool prealloc, force_prealloc, is_mapped;
    DECLARE_BITMAP(host_nodes, MAX_NODES + 1);
    HostMemPolicy policy;

    MemoryRegion mr;         // Owned MemoryRegion
};
```

A section of Host memory defined by QOM provides memory for virtual memory sticks. It can be managed through QMP or QEMU command line.


#### Memory initialization

On the premise that KVM is turned on, QEMU initializes the memory through the following process:

```
main => configure_accelerator => kvm_init => kvm_memory_listener_register(s, &s->memory_listener, &address_space_memory, 0) initialization
kvm_state.memory_listener
                                          => kml->listener.region_add = kvm_region_add                      sets the operation for the listener
                                          => memory_listener_register                                       initializes the listener and binds it to address_space_memory
                                          => memory_listener_register(&kvm_io_listener, &address_space_io)  initialize kvm_io_listener and bind to address_space_io
     => cpu_exec_init_all => memory_map_init                                        creates system_memory("system") and system_io("io") two global MemoryRegion
                                 => address_space_init                              initialize address_space_memory("memory") and address_space_io("I/O") AddressSpace, and use system_memory and system_io as root
                                    => memory_region_transaction_commit             commits the modification, causing a change in the address space
```

Before further analysis, we first introduce the three structures involved: AddressSpace, MemoryRegion and MemoryRegionSection:


#### AddressSpace

```c
struct AddressSpace {
    /* All fields are private. */
    struct rcu_head rcu;
    char *name;
    MemoryRegion *root;
    int ref_count;
    bool malloced;

    /* Accessed via RCU.   */
    struct FlatView *current_map;                                // Point to the currently maintained FlatView, compared as old in address_space_update_topology

    int ioeventfd_nb;
    struct MemoryRegionIoeventfd *ioeventfds;
    struct AddressSpaceDispatch *dispatch;                       // Responsible for finding HVA according to GPA
    struct AddressSpaceDispatch *next_dispatch;
    MemoryListener dispatch_listener;
    QTAILQ_HEAD(memory_listeners_as, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};
```

As the name implies, it is used to represent a piece of address space of a virtual machine, such as memory address space and IO address space. Each AddressSpace generally contains a series of MemoryRegions: The root of the AddressSpace points to the root-level MemoryRegion, which may have several subregions of its own, thus forming a tree structure.

As mentioned above, memory_map_init is called in the memory initialization process, which initializes address_space_memory and address_space_io, where:

* The root of address_space_memory is system_memory.
* The root of address_space_io is system_io.


#### MemoryRegion

```c
struct MemoryRegion {
    Object parent_obj;                                                  // Inherited from Object

    /* All fields are private - violators will be prosecuted */

    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool rom_device;                                                    // Read-only
    bool flush_coalesced_mmio;
    bool global_locking;
    uint8_t dirty_log_mask;                                             // dirty map type
    RAMBlock *ram_block;                                                // Point to the corresponding RAMBlock
    Object *owner;
    const MemoryRegionIOMMUOps *iommu_ops;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;                                            // Points to the parent MemoryRegion
    Int128 size;                                                        // Memory area size
    hwaddr addr;                                                        // The offset in the parent MemoryRegion (see memory_region_add_subregion_common)
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;                                                // Points to the entity MemoryRegion
    hwaddr alias_offset;                                                // The offset of the starting address (GPA) in the entity MemoryRegion
    int32_t priority;
    QTAILQ_HEAD(subregions, MemoryRegion) subregions;                   // subregion linked list
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_HEAD(coalesced_ranges, CoalescedMemoryRange) coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    QLIST_HEAD(, IOMMUNotifier) iommu_notify;
    IOMMUNotifierFlag iommu_notify_flags;
};
```

Memory Region represents a section of memory in the Guest memory layout and has a logical (Guest) meaning.

In the process of initializing the VM, the corresponding MemoryRegion is established:

```
pc_init1 / pc_q35_init => pc_memory_init => memory_region_allocate_system_memory                        Initialize MemoryRegion and allocate memory for it
                                         => memory_region_init_alias => memory_region_init              Initialize alias MemoryRegion
                                         => memory_region_init                                          Initialize MemoryRegion
                                         => memory_region_init_ram => memory_region_init                Initialize MemoryRegion and allocate Ramblock
```


##### memory_region_allocate_system_memory

For non-NUMA-based VMs, directly allocate memory

```
=> allocate_system_memory_nonnuma => memory_region_init_ram_from_file / memory_region_init_ram          Allocate MemoryRegion corresponding to Ramblock memory
=> vmstate_register_ram                                                                                 Set the idstr of the RAMBlock according to the name of the region
```

For NUMA, HostMemoryBackend needs to be set after allocation

```
=> memory_region_init
=> memory_region_add_subregion                          Traverse the memory HostMemoryBackend of all NUMA nodes, and use those whose mr members are not empty as subregions of the current MemoryRegion, and the offset starts from 0 to increase
=> vmstate_register_ram_global => vmstate_register_ram  Set the idstr of the RAMBlock according to the name of the region
```

##### MemoryRegion Type

MemoryRegion could be divided into the following three types：

* Root-level MemoryRegion: It is initialized directly through memory_region_init without its own memory, which is used to manage subregions. Such as system_memory.
* Root-level MemoryRegion: It is initialized directly through memory_region_init without its own memory, which is used to manage subregions. Such as system_memory.
* Root-level MemoryRegion: It is initialized directly through memory_region_init without its own memory, which is used to manage subregions. Such as system_memory.

The common MemoryRegion relationship in the code is：

```
                  alias
ram_memory (pc.ram) - ram_below_4g(ram-below-4g)
                    - ram_above_4g(ram-above-4g)

             alias
system_io(io) - (pci0-io)
              - (isa_mmio)
              - (isa-io)
              - ...

                     sub
system_memory(system) - ram_below_4g(ram-below-4g)
                      - ram_above_4g(ram-above-4g)
                      - pcms->hotplug_memory.mr        Hot-swappable memory

          sub
rom_memory - isa_bios(isa-bios)
           - option_rom_mr(pc.rom)

```

At the same time, map AddressSpace to FlatView to get several MemoryRegionSections, call kvm_region_add to register MemoryRegionSection in KVM.


##### MemoryRegionSection

```c
struct MemoryRegionSection {
    MemoryRegion *mr;                           // Point to the owning MemoryRegion
    AddressSpace *address_space;                // Belonging to AddressSpace
    hwaddr offset_within_region;                // The offset of the starting address (HVA) within the MemoryRegion
    Int128 size;
    hwaddr offset_within_address_space;         // The offset within the AddressSpace, if the AddressSpace is system memory, it is the GPA starting address
    bool readonly;
};
```

MemoryRegionSection points to a part of MemoryRegion ([offset_within_region, offset_within_region + size]), which is the basic unit of registration to KVM.

MemoryRegionSection points to a part of MemoryRegion ([offset_within_region, offset_within_region + size]), which is the basic unit of registration to KVM.

Looking back at the memory initialization process, the job is very simple. create some AddressSpace and bind listener. Create the corresponding MemoryRegion as the root of the AddressSpace. Finally, submit the modification to change the address space and update it to KVM. The following will be divided into points.



##### KVMMemoryListener

During the initialization process, memory_listener and kvm_io_listener were registered for address_space_memory and address_space_io respectively. The former type is KVMMemoryListener and the latter type is MemoryListener:

```c
typedef struct KVMMemoryListener {
    MemoryListener listener;
    KVMSlot *slots;
    int as_id;
} KVMMemoryListener;

struct MemoryListener {void (*begin)(MemoryListener *listener);
    void (*commit)(MemoryListener *listener);
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_start)(MemoryListener *listener, MemoryRegionSection *section,
                      int old, int new);
    void (*log_stop)(MemoryListener *listener, MemoryRegionSection *section,
                     int old, int new);
    void (*log_sync)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_global_start)(MemoryListener *listener);
    void (*log_global_stop)(MemoryListener *listener);
    void (*eventfd_add)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*eventfd_del)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*coalesced_mmio_add)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);
    void (*coalesced_mmio_del)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);
    /* Lower = earlier (during add), later (during del) */
    unsigned priority;
    AddressSpace *address_space;
    QTAILQ_ENTRY(MemoryListener) link;
    QTAILQ_ENTRY(MemoryListener) link_as;
};
```

It can be seen that the main body of the KVMMemoryListener is the MemoryListener, and the MemoryListener contains a large number of function pointers to point to the callback function that is called when the address_space member changes.

It can be seen that the main body of the KVMMemoryListener is the MemoryListener, and the MemoryListener contains a large number of function pointers to point to the callback function that is called when the address_space member changes.

In fact, any operation on AddressSpace and MemoryRegion starts with memory_region_transaction_begin and ends with memory_region_transaction_commit.

These operations include: enabling, destructuring, adding and deleting eventfd, adding and deleting subregions, changing attributes (flag), setting size, opening dirty log, etc., such as:

* memory_region_add_subregion
* memory_region_del_subregion
* memory_region_set_readonly
* memory_region_set_enabled
* memory_region_set_size
* memory_region_set_address
* memory_region_set_alias_offset
* memory_region_readd_subregion
* memory_region_update_container_subregions
* memory_region_set_log
* memory_region_finalize
* ...

These operations include: enabling, destructuring, adding and deleting eventfd, adding and deleting subregions, changing attributes (flag), setting size, opening dirty log, etc., such as:

* address_space_init
* address_space_destroy

##### memory_region_transaction_begin

```
=> qemu_flush_coalesced_mmio_buffer => kvm_flush_coalesced_mmio_buffer
=> ++memory_region_transaction_depth
```

KVM has done batch optimization for some MMIO: When KVM encounters MMIO and VMEXIT, it records the MMIO operation in the kvm_coalesced_mmio structure, and then stuffs it into the kvm_coalesced_mmio_ring without exiting to QEMU. Until you return to QEMU one time, the moment before you want to update the memory space, take out the kvm_coalesced_mmio in kvm_coalesced_mmio_ring and do it again to ensure memory consistency. This is what kvm_flush_coalesced_mmio_buffer does.


##### memory_region_transaction_commit

```
=> --memory_region_transaction_depth
=> 如果 memory_region_transaction_depth        Is 0 and memory_region_update_pending is greater than 0
    => MEMORY_LISTENER_CALL_GLOBAL(begin, Forward)        Call the begin function of all listeners in the global list memory_listeners from front to back
    => 对 address_spaces 中的所有 address space，调用 address_space_update_topology ，Update the slot information maintained in QEMU and KVM.
    => MEMORY_LISTENER_CALL_GLOBAL(commit, Forward)       Call the commit function of all listeners in the global list memory_listeners from back to front
```

Call the corresponding function of listener to update the address space.

##### address_space_update_topology

```
=> address_space_get_flatview                             Get the original FlatView(AddressSpace.current_map)
=> generate_memory_topology                               Generate new FlatView
=> address_space_update_topology_pass                     Relatively new and old FlatView, perform corresponding operations on the inconsistent FlatRange.
```

Since AddressSpace is a tree structure, address_space_update_topology is called to map (flatten) the tree structure to a linear address space using the FlatView model. Compare the new and old FlatView, perform the corresponding operation on the inconsistent FlatRange, and finally operate the KVM.

##### generate_memory_topology
```
➔ addrrange_make         Create an address space with a start address of 0 and an end address of 2^64 as the guest's linear address space 
➔ render_memory_region   Starting from the root-level region, recursively map the region to the linear address space to generate a FlatRange to form a FlatView  
➔ faltview_simplify      Combine consecutive FlatRange in FlatView into one
```

The root member of AddressSpace is the root-level MemoryRegion of the address space, and generate_memory_topology is responsible for flatterening its tree structure so that it can be mapped to a linear address space and get FlatView.

##### address_space_update_topology_pass
If you want to compare the new and old FlatRange of tthe AddressSpace, traverse the listeners of the AddressSpace from front to back or from back to front and call the correspoding callback function.

```
➔ MEMORY_LISTENER_UPDATE_REGION ➔ section_from_flat_range   Construct MemoryRegionSection according to the range of FlatRange
                                ➔ MEMORY_LISTENER_CALL
```

For example, as we mentioned, in the initalization process, kvm_state.memory_listener is registered as the listener of the address_space_memory and added to the listener of AddressSpace.

If the callback parameter in MEMORY_LISTENER_UPDATE_REGION is region_add, then memory_listener.region_add(kvm_region_add) is called.

##### kvm_region_add
```
➔ kvm_set_phys_mem ➔ kvm_lookup_overlapping_slot
                   ➔ Calculating HVA
                   ➔ kvm_set_user_memory_region => kvm_vm_ioctl(s, KVM_SET_USER_MEMORY_REGION, &mem)

```

kvm_lookup_overlapping_slot is used to determine whether the new address range of local section(GPA) overlaps with the existing KVMSlot(kml->slots).

Aussuming that the original slot can be divied into three parts, prefix slot + overlap slot + sufix slot, it overlaps with the overlap slot.

For complete overlap, there are both prefix slot and suffix slot. No need to register a new slot.

For partial overlap, there are prefix slot = 0 and suffix slot = 0. Then it perfroms the follwing process:

1. Delete the original slot
2. Register the prefix slot or suffix slot
3. Register the overlap slot

Of course, if there is no overlap, just register a new slot directly. And then update the slot to the correspoding kvm_memory_slot of KVM through kvm_vm_ioctl(KVM_SET_USER_MEMORY_REGION).

The maintance of the slot structure in QEMU also needs to be updated. For original slot, because it is an kml->slots arrays, it can be modified directly in kvm_set_phys_mem. For slots that are not in kml->slots, such as prefix, suffix and overlap, you need to call the kvm_alloc_slot ➔ kvm_get_free_slot to find a blank(memory_size == 0) in kml->slots and set the slot.

##### kvm_set_phys_mem ➔ kvm_set_user_memory_region
KVM specifies that the parameter for updaing the memory slot as kvm_userspace_memory_region.

```c
struct kvm_userspace_memory_region {
    __u32 slot;                       // kvm_memory_slot id
    __u32 flags;
    __u64 guest_phys_addr;            // GVA
    __u64 memory_size;     /* bytes */ // Size
    __u64 userspace_addr;  /* start of the userspace allocated memory */ // HVA
};
```

It is calculated and filled in the process of kvm_set_phys_mem ➔ kvm_set_user_memory_region. And the process is as follows:

1. According to the starting HVA(memory_region_get_ram_ptr) of the region + the offset of the region section in the region(offset_within_region) + page alignment correction(delta) to get the real starting HVA of section, fill in userspace_addr.

In memory_region_get_ram_ptr, if the current region is the alias of anothre region, it will be traced upwards until it reaches the non-alias region(physical region). Add the alias_offset in the traceback process to get the offset of the current region in the entity region.

Since the entity region has a corresspoding RAMBlock, call qemu_map_ram_ptr to add the host and toal offset of the RAMBlock correspoding to the entity region to get the starting HVA of the current region.

2. Get the real GPA of the section according to the offset of the region sectio in the AddressSpace(offset_within_address_space) + page alignment correction(delta), and fill in start_addr.

3. Get the real size of the section according to the size of the region section and page alignment correction, and fill it in memory_size.

### RAMBlock
MemoryRegion represents a section of memory in the guest memory layout, which has a logical meaning. So the acutal meaning is that who maintains the actual memory information correspoding to this piece of memory?

We can find that there is a ram_block member in MemoryRegion, which is a pointer of type RAMBlock. RAMBlock is responsible for maintaining the actual memory information like the HVA and GPA. For example, in the process of to calculating userspace_addr, the starting HVA of the calculation region must find the corresponding RAMBlock and get its host member. RAMBlock is defined as follows:

```c
struct RAMBlock {
    struct rcu_head_rcu;
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized) (const char*, uint64_t length, void *host);
    uint32_t flag;
    char idstr[256];
    QLIST_ENTRY(RAMBlock) next;
    int fd;
    size_t page_size;
}
```

MemoryRegion will call memory_region_* to initialize the MemoryRegion structure. The common functions are as follows:

* memory_region_init_ram: RAMBlock.host is NULL that created by qemu_ram_alloc
* memory_region_init_ram_from_file: qemu_ram_alloc_from_file created by RAMBlock call file_ram_alloc to allocate memory using the file of the correspoding path. The hugepage device file(ex: /dec/hugepages) is specified by the `-mem-path` parameter to use hugepage.
* memory_region_init_ram_ptr: 
* memory_region_init_resizeable_ram: 

qemu_ram_alloc_* (qemu_ram_alloc / qemu_ram_alloc_from_file / memory_region_init_ram_ptr / memory_region_init_resizeable_ram) eventually be called to qemu_ram_alloc_internal ➔ ram_block_add. If it finds that host is NULL, it calls phys_mem_alloc(qemu_anon_ram_alloc) to allocate memory. After making the host point something, insert the RAMBlock into ram_list.blocks.

##### qemu_anon_ram_alloc
➔ qemu_ram_mmap(-1, size, QEMU_VMALLOC_ALIGN, false) ➔ mmap

Use mmap to allocate memory of size in the process address space of QEMU.

### RAMList
ram_list is a global variable that maintains all RAMBlock form using linked list.

```c
RAMList ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };

typedef struct RAMList {
    QemuMutex mutex;
    RAMBlock *mru_block;
    /* RCU-enabled, writes protected by the ramlist lock. */
    QLIST_HEAD(, RAMBlock) blocks;                        // RAMBlock linked list
    DirtyMemoryBLocks *dirty_memory[DIRTY_MEMORY_NUM];    // Record dirty page information for VGA / TCG / Live Migration
    uint32_t version;                                     // Add 1 for every change
} RAMList;
extern RAMList ram_list;
```

Note:
* VGA: Graphics card emulation tracks dirty video memory through dirty_memory to redraw the interface.
* TCG: Dynamic translator tracks the self-tuning code and recompiles it when upstream instruction changes.
* Live migration: It tracks dirty pages through dirty_memory and retransmits after the diry pages are changed.

##### AddressSpaceDispatch
```
address_space_init ➔ address_space_init_dispatch ➔ as ➔ dispatch_listener = (MemoryListener) {
    .begin = mem_begin,
    .commit = mem_commit,
    .region_add = mem_add,
    .region_nop = mem_add,
    .priority = 0,
}; ➔ memory_listener_register(as ➔ dispatch_listener)
```

In addition to kvm_state.memory_listener bound to address_listener, dispatch_listener will also be created and bound. The listener is implemented in order to find the corresponding HVA according to the GPA when the virtual machine exits.

When memory_region_transaction_commit calls the begin function of each listener, mem_begin is called.

```
➔ g_new0(AddressSpaceDispatch, 1)                Create AddressSpaceDispatch structure as next_dispatch member of AddressSpace 
```

The AddressSpaceDispatch structure is as follows:

```c
struct AddressSpaceDispatch {
    struct rcu_head rcu;

    MemoryRegionSection *mru_section;
    /*
    This is a multi-level map on the physical address space.
    The bottom level has pointers to MemoryRegionSections.
    */
    PhysPageEntry phys_map;
    PhysPageMap map;           // GPA ➔ HVA mapping, implemented through multi-level page tables
    AddressSpace *as;
}
```

The map member is multi-level(6 level) page table, and the last level page table points to MemoryRegionSection.

When address_spcae_update_topology_pass processes addition, calls mem_add.

So call register_subpage / register_multipage to register the page in the page table.

```
➔ If the subpage of the MemoryRegion to which the MemoryRegionSectin belongs does not exist
  ➔ subpage_init                                      Create subpage
  ➔ phys_page_set ➔ phys_map_node_reserve             Allcation page directory entry
                  ➔ phys_page_set_level               Fill the page table from L5 to L0

➔ If it exists
  ➔ container_of(existing->mr, suboage_t, iomem)      Take out
➔ subpage_register                                    subpage_register set subpage
```

Therefore, after exiting from KVM to QEMU, you can find the correspoding MemoryRegionSection through AddressSpaceDispatch.map, and then find the corresspoding HVA.



## KVM


### kvm_vm_ioctl_set_memory_region

Add memory. Called when KVM receives an ioctl from KVM_SET_USER_MEMORY_REGION(KVM_SET_MEMORY_REGION has been replaced because fine-grained control is not supported).

Incoming parameters are as follows：

```c
struct kvm_userspace_memory_region {
    __u32 slot;                                                             // id corresponding to kvm_memory_slot
    __u32 flags;
    __u64 guest_phys_addr;                                                  // GPA
    __u64 memory_size; /* bytes */                                          // size
    __u64 userspace_addr; /* start of the userspace allocated memory */     // HVA
};
```

flags Options：

* Declares KVM_MEM_LOG_DIRTY_PAGES for write tracking to Region. Read them when KVM_GET_DIRTY_LOG is provided.
* If KVM_MEM_READONLY supports readonly(KVM_CAP_READONLY_MEM), VMEXIT(KVM_EXIT_MMIO) is triggered when this Region is written.

kvm_vm_ioctl_set_memory_region => kvm_set_memory_region => __kvm_set_memory_region

This function determines user actions based on npages(included in the region) and the original npages：

#### KVM_MR_CREATE
If you have a page now and you don't have one, create and initialize a slot to add more memory space.

#### KVM_MR_DELETE
If there is no page now, mark the slot as KVM_MEMSLOT_INVALID to clear the memory area.

#### KVM_MR_FLAGS_ONLY / KVM_MR_MOVE
If you have a page now and you have one, you can modify the memory area, if only the flag changes, KVM_MR_FLAGS_ONLY, and if it is currently possible only KVM_MEM_LOG_DIRTY_PAGES, select whether to create or release the dirty_bitmap according to the flag.

If GPA changes, KVM_MR_MOVE must be moved. In fact, the original slot is marked as KVM_MEMSLOT_INVALID and a new one is added.

The new/modified slots are updated with install_new_memslots.

#### kvm_memory_slot

The slot for the __kvm_set_memory_region operation is the default uint of memory management in the KVM and is defined as follows：

```c
struct kvm_memory_slot {
    gfn_t base_gfn;                     // start gfn for slot
    unsigned long npages;               // page number
    unsigned long *dirty_bitmap;        // dirty page bitmap
    struct kvm_arch_memory_slot arch;   // configuration correlation, including rmap and lpage_info, etc.
    unsigned long userspace_addr;       // Corresponding starting HVA
    u32 flags;
    short id;
};


struct kvm_arch_memory_slot {struct kvm_rmap_head *rmap[KVM_NR_PAGE_SIZES];              // reverse link
    struct kvm_lpage_info *lpage_info[KVM_NR_PAGE_SIZES - 1];   // maintaining whether the next levvel of page table is turned off hugepage
    unsigned short *gfn_track[KVM_PAGE_TRACK_MAX];
};
```

slot is sotred in kvm->memslots[as_id]->memslots[id]->memslots[id] where as_is is address space id. In fact, the typical architecture always has only one address space, as_id always takes 0. Only x86 requires two address space, as_id = 0 is normal address space, and as_id = 1 is the SRAM space dedicated to SMM mode, and id is the slot id. Memory for all of these configurations is allocated to kvm_create_vm. It is initialized here.


### Memory Management Unit (MMU)

#### Initialization

```
kvm_init => kvm_arch_init => kvm_mmu_module_init => configure mmu_page_header_cache as cache
                                                 => register_shrinker(&mmu_shrinker)                registration recovery function


kvm_vm_ioctl_create_vcpu =>
kvm_arch_vcpu_create => kvm_x86_ops->vcpu_create (vmx_create_vcpu) => init_rmode_identity_map       Configuring a 1024-page equivalent map for real mode
                                                                   => kvm_vcpu_init => kvm_arch_vcpu_init => kvm_mmu_create
kvm_arch_vcpu_setup => kvm_mmu_setup => init_kvm_mmu => init_kvm_tdp_mmu                            set properties and functions in vcpu->arch.mmu if two dimensional paging(EPT) is supported and initialized
                                                     => init_kvm_softmmu => kvm_init_shadow_mmu     Otherwise, initialize the SPT
```


##### kvm_mmu_create

Initializes mmu-related information on a per-vcpu basis. Their definitions in vcpu include the following：

```c
struct kvm_vcpu_arch {
    ...
    /*
     * Paging state of the vcpu
     *
     * If the vcpu runs in guest mode with two level paging this still saves
     * the paging mode of the l1 guest. This context is always used to
     * handle faults.
     */
    struct kvm_mmu mmu;

    /*
     * Paging state of an L2 guest (used for nested npt)
     *
     * This context will save all necessary information to walk page tables
     * of the an L2 guest. This context is only initialized for page table
     * walking and not for faulting since we never handle l2 page faults on
     * the host.
     */
    struct kvm_mmu nested_mmu;

    /*
     * Pointer to the mmu context currently used for
     * gva_to_gpa translations.
     */
    struct kvm_mmu *walk_mmu;

    // The following is used to speed up deployment of commonly used data structures
    // Used to allocate pte_list_desc, which is a chain table entry in reverse map chain table parent_ptes, from mmu_set_spte => rmap_add => pte_list_add
    struct kvm_mmu_memory_cache mmu_pte_list_desc_cache;
    // Used to allocate pages as kvm_mmu_page.spt
    struct kvm_mmu_memory_cache mmu_page_cache;
    // Used to allocate kvm_mmu_page as a table of pages
    struct kvm_mmu_memory_cache mmu_page_header_cache;
    ...
}
```

Cache is used to speed up the allocation of commonly used data structures in page tables. These caches call mmu_topup_memory_caches when MMU(kvm_mmu_load) is initialized, page fault(tdp_page_fault) is generated, and so on to ensure that each cache is sufficient.

```c
// Ensure that each cache is sufficient
static int mmu_topup_memory_caches(struct kvm_vcpu *vcpu)
{
    // r not zero means allocation from slab /__get_free_page failed, direct return error
    int r;
    // if vcpu->arch.mmu_pte_list_desc_cache is insufficient, allocate from pte_list_desc_cache
    r = mmu_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
                   pte_list_desc_cache, 8 + PTE_PREFETCH_NUM);
    if (r)
        goto out;
    // if vcpu->arch.mmu_page_cache is insufficient, deploy directly through __get_free_page
    r = mmu_topup_memory_cache_page(&vcpu->arch.mmu_page_cache, 8);
    if (r)
        goto out;
    // Deploy from mmu_page_header_cache if vcpu->arch.mmu_page_header_cache is insufficient
    r = mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
                   mmu_page_header_cache, 4);
out:
    return r;
}
```

Two global slabs, pte_list_desc_cache and mmu_page_header_cache, are created in kvm_mmu_module_init as cache source for vcpu->arch.mmu_pte_list_desc_cache and vcpu->arch.mmu_page_header_cache.

Allocated slabs can be found at host via `cat /proc/slabinfo`：

```
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
kvm_mmu_page_header    576    576    168   48    2 : tunables    0    0    0 : slabdata     12     12      0
```



#### Load Page Table

vm_vm_ioctl_create_vcpu is only initialized for mmu, such as setting vcpu->arch.mmu.root_hpa to INVALID_PAGE and setting this value to VM(VMLAUNCH/VMRESUME).

```
vcpu_enter_guest => kvm_mmu_reload => kvm_mmu_load => mmu_topup_memory_caches                       ensure that each cache is sufficient
                                                   => mmu_alloc_roots => mmu_alloc_direct_roots     allocate one kvm_mmu_page if the root page table does not exist
                                                   => vcpu->arch.mmu.set_cr3 (vmx_set_cr3)          for EPT, load the HPA of spt(struct page) on this page to VMCS.
                                                                                                    for SPT, load the HPA of spt(struct page) on this page into cr3
                 => kvm_x86_ops->run (vmx_vcpu_run)
                 => kvm_x86_ops->handle_exit (vmx_handle_exit)
```


#### kvm_mmu_page

Table of pages, see Documentation/virtual/kvm/mmu.txt for more information.

```c
struct kvm_mmu_page {
    struct list_head link;                          // add kvm->arch.active_mmu_pages or invalid_list to indicate the status of the current page
    struct hlist_node hash_link;                    // add to vcpu->kvm->arch.mmu_page_hash to provide quick lookup

    /*
     * The following two entries are used to key the shadow page in the
     * hash table.
     */
    gfn_t gfn;                                      // gfn corresponding to the starting address of the management address range
    union kvm_mmu_page_role role;                   // Basic information, including hardware attributes and layers to which they belong

    u64 *spt;                                       // The address that points to the structure page, which contains all page table entries (pte). At the same time, page->private points to this kvm_mmu_page
    /* hold the gfn of each spte inside spt */
    gfn_t *gfns;                                    // gfn corresponding to all page table entries (pte)
    bool unsync;                                    // Use to indicate whether the page table entry (pte) is synchronized with guest on the last level of the page table. (guest whether tlb has been updated)
    int root_count;          /* Currently serving as active root */ // Use for top-level page tables and statistics on how many EPTPs are directed to themselves
    unsigned int unsync_children;                   // pte of unsync on page table
    struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */ // reverse mapping (rmap), maintaining table entries pointing to one's parent

    /* The page is obsolete if mmu_valid_gen != kvm->arch.mmu_valid_gen.  */
    unsigned long mmu_valid_gen;                    // Algebraically, less than kvm->arch.mmu_valid_gen indicates that it is invalid

    DECLARE_BITMAP(unsync_child_bitmap, 512);       // Unsync's spte bitmap on the page table.

#ifdef CONFIG_X86_32
    /*
     * Used out of the mmu-lock to avoid reading spte values while an
     * update is in progress; see the comments in __get_spte_lockless().
     */
    int clear_spte_count;                           // At 32bit, the modification of the spte is atommic, so this count detects if it is being modified and requires redo if it is modified
#endif

    /* Number of writes since the last time traversal visited this page.  */
    atomic_t write_flooding_count;                  // Statistics the number of emulations since the last use and drops this page to unmap if it exceeds a certain number
};

union kvm_mmu_page_role {
    unsigned word;
    struct {
        unsigned level:4;           // The hierarchy in which the page is located
        unsigned cr4_pae:1;         // cr4.pae, 1 denotes the use of 64bit gpte
        unsigned quadrant:2;        // if cr4.pae=0, the gpte is 32bit, but the spte is 64bit, so you need to use multiple sptees to represent a gpte. This field indicates the number of blocks in the gpte
        unsigned direct:1;
        unsigned access:3;          // Access rights
        unsigned invalid:1;         // It doesn't work. Once the unpin is destroyed, it won't work.
        unsigned nxe:1;             // efer.nxe
        unsigned cr0_wp:1;          // cr0.wp, write protection
        unsigned smep_andnot_wp:1;  // cr4.smep && !cr0.wp
        unsigned smap_andnot_wp:1;  // cr4.smap && !cr0.wp
        unsigned :8;

        /*
         * This is left at the top of the word so that
         * kvm_memslots_for_spte_role can extract it with a
         * simple shift.  While there is room, give it a whole
         * byte so it is also faster to load it from memory.
         */
        unsigned smm:8;             // In system management mode
    };
};
```


#### EPT Violation

When a guest visits a Guest physical page for the first time, since there is no mapping from GVA to GPA, a page fault of the Guest OS is triggered. Then Guest OS will establish the corresponding pte and repair the page tables at all levels, and finally access the corresponding GPA. Since there is no mapping from GPA to HVA, EPT Violation is triggered. EPT violation changes control from guest mode to host mode.

```C
arch/x86/kvm/x86.c

static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
    ...
    kvm_x86_ops->run(vcpu); // Run Guest
    ...
    r = kvm_x86_ops->handle_exit(vcpu); // In intel cpu, .handle_exit = vmx_handle_exit
}
```
In `vmx_handle_exit`, KVM find a appropriate handler in the `kvm_vmx_exit_handlers[]`. When exit_reason is EXIT_REASON_EPT_VIOLATION, `handle_ept_violation` will handle this VMEXIT.
```C
arch/x86/kvm/vmx.c

static int (*const kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
    ...
    [EXIT_REASON_EPT_VIOLATION]       = handle_ept_violation
}

static int vmx_handle_exit(struct kvm_vcpu *vcpu)
{
    ...
    if (exit_reason < kvm_vmx_max_exit_handlers
    && kvm_vmx_exit_handlers[exit_reason])
        return kvm_vmx_exit_handlers[exit_reason](vcpu);
}
```
In `handle_ept_violation`, KVM get the exit reason and the guest physical address where the EPT violation occured. Then KVM parse the exit code and pass it to `kvm_mmu_page_fault`.
```C
arch/x86/kvm/vmx.c

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
    unsigned long exit_qualification;
    gpa_t gpa;
    u64 error_code;

    /* Get the reason for EPT exit. EXIT_QUALIFICATION is a supplement to Exit reason, see Vol. 3C 27-9 Table 27-7 for details */
    exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
    ...

    /* Get the GPA of the page fault */
    gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
    ...

    return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0); // tdp_page_fault
}
```
When TDP(Two-Dimensional-Paging) is enabled, kvm_mmu_page_fault call `tdp_page_fault`.
```C
arch/x86/kvm/mmu.c

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t cr2, u64 error_code,
               void *insn, int insn_len)
{
    ...
    if (r == RET_PF_INVALID) {
        r = vcpu->arch.mmu.page_fault(vcpu, cr2, lower_32_bits(error_code), // tdp_page_fault
                          false);
        WARN_ON(r == RET_PF_INVALID);
    }
    ...
}
```

##### tdp_page_fault
It can be found that there are two main steps. The first step is finding the physical page corresponding to the GPA, if not, KVM will allocate a new page. The second step is updating the EPT with host physical page. Each step corresponds to these functions `try_async_pf`, `__direct_map`.
```C
arch/x86/kvm/mmu.c

static int tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code,
              bool prefault)
{
    gfn_t gfn = gpa >> PAGE_SHIFT;
    int write = error_code & PFERR_WRITE_MASK;
    bool map_writable;
    ...

#ifdef CONFIG_KVM_DSM
    /* Disable large pages for DSM */
    if (vcpu->kvm->arch.dsm_enabled)
            force_pt_level = true;
#endif
    /* When force_pt_level == true, return PT_PAGE_TABLE_LEVEL(=1)*/
    level = mapping_level(vcpu, gfn, &force_pt_level);
    ...

    /* converts gfn to pfn, if not exists allocate a new page */
    if (try_async_pf(vcpu, prefault, gfn, gpa, &pfn, write, &map_writable))
        return RET_PF_RETRY;

    spin_lock(&vcpu->kvm->mmu_lock);
    ...

    /* Update EPT table, adding new mapping relationship to EPT layer by layer */
    r = __direct_map(vcpu, write, map_writable, level, gfn, pfn, prefault, dsm_access);
    spin_unlock(&vcpu->kvm->mmu_lock);
    ...
}
```
=> __direct_map Update EPT, adding new mapping relationship to EPT layer by layer
    => for_each_shadow_entry starting from level4 (root), complete the page table layer by layer, for each layer:
        => mmu_set_spte For the page table of level1, the page table entry is definitely missing, so there is no need to judge directly to fill in the starting hpa of pfn
        => is_shadow_present_pte If the next-level page table page does not exist, that is, the current page table entry has no value (*sptep = 0)
            => kvm_mmu_get_page allocates a page table page structure
            => link_shadow_page fills the HPA of the new page table into the current page table entry (sptep)

##### try_async_pf
1. Find the corresponding memslot according to gfn
2. Using the memslot, get the starting HVA corresponding to gfn.
3. Find a physical page mapped with HVA. There are two types of function to do  this: `hva_to_pfn_fast` and `hva_to_pfn_slow`. hva_to_pfn_fast actually calls __get_user_pages_fast and will try to find the physical page. If it succeedis, pin(increase ref count) the page. If it fails, then fall back to hva_to_pfn_slow. It will allocate and pin a new page.
4. If the allocation is successful, call page_to_pfn to get the allocated pages's pfn

```C
arch/x86/kvm/mmu.c

static bool try_async_pf(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
             gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable)
{
    struct kvm_memory_slot *slot;
    bool async;
    ...

    /* Get memory slot from gfn */
    slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

    /* Inside the __gfn_to_pfn_memslot
     * => __gfn_to_pfn_memslot
     *   => hva_to_pfn
     *     => hva_to_pfn_fast (If physical page is already exist, else fallback to slow path)
     *       => __get_user_pages_fast
     *       => page_to_pfn
     *     => hva_to_pfn_slow (if physical page is not exist, allocate a new page)
     *       => __get_user_pages
     *       => page_to_pfn
     */
    *pfn = __gfn_to_pfn_memslot(slot, gfn, false, &async, write, writable);
}
```

##### __direct_map

Complete the page table related to the GPA in the EPT through the iterator `kvm_shadow_walk_iterator` and macro `for_each_shadow_entry`.

```c
arch/x86/kvm/mmu.c

struct kvm_shadow_walk_iterator {
    u64 addr;           // The GPA of a page fault occurs, the iteration process is to fill in all the page table items involved in the GPA
    hpa_t shadow_addr;  // The HPA of the current page table entry is set to vcpu->arch.mmu.root_hpa in shadow_walk_init
    u64 *sptep;         // Point to the current page table entry, updated in shadow_walk_okay
    int level;          // The current level, set to 4 in shadow_walk_init (x86_64 PT64_ROOT_LEVEL), and subtract 1 in shadow_walk_next
    unsigned index;     // The index in the current level page table, updated in shadow_walk_okay
};
```
```C
arch/x86/kvm/mmu.c

#define for_each_shadow_entry(_vcpu, _addr, _walker)    \
        for (shadow_walk_init(&(_walker), _vcpu, _addr);        \
             shadow_walk_okay(&(_walker));                      \
             shadow_walk_next(&(_walker)))

static void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
                             struct kvm_vcpu *vcpu, u64 addr)
{
        iterator->addr = addr;
        iterator->shadow_addr = vcpu->arch.mmu.root_hpa;
        iterator->level = vcpu->arch.mmu.shadow_root_level;

        ...
}

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
        if (iterator->level < PT_PAGE_TABLE_LEVEL)
                return false;

        iterator->index = SHADOW_PT_INDEX(iterator->addr, iterator->level);
        iterator->sptep = ((u64 *)__va(iterator->shadow_addr)) + iterator->index;
        return true;
}

static void __shadow_walk_next(struct kvm_shadow_walk_iterator *iterator,
                               u64 spte)
{
        if (is_last_spte(spte, iterator->level)) {
                iterator->level = 0;
                return;
        }

        iterator->shadow_addr = spte & PT64_BASE_ADDR_MASK;
        --iterator->level;
}

static void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
        __shadow_walk_next(iterator, *iterator->sptep);
}
```

In each iteration, shadow_addr and level is updated by shadow_walk_next. Then, index and sptep is calculated by `shadow_walk_okay`. For example, for GPA (such as 0xfffff001), the binary is:
```
000000000 000000011 111111111 111111111 000000000001
    PML4       PDPT        PD        PT       Offset
```
- When level = 4, index is 0   (000000000)
- When level = 3, index is 3   (000000011)
- When level = 2, index is 511 (111111111)
- When level = 1, index is 511 (111111111)

sptep will point to the page table entry corresponding to the GPA in the current level page table. Our purpose is to fill the GPA of the next level page table into the page table entry (ie set *sptep). Because EPT fault occured, there may be a problem that the next-level page table page does not exist (*sptep == 0). At that time, a new page is allocated for a page table, and then KVM fill the empty entry in the EPT table.

```C
arch/x86/kvm/mmu.c

static int __direct_map(struct kvm_vcpu *vcpu, int write, int map_writable,
                        int level, gfn_t gfn, kvm_pfn_t pfn, bool prefault, int dsm_access)

{
        struct kvm_shadow_walk_iterator iterator;
        struct kvm_mmu_page *sp;
        int emulate = 0;
        gfn_t pseudo_gfn;

        ...

        for_each_shadow_entry(vcpu, (u64)gfn << PAGE_SHIFT, iterator) {
                if (iterator.level == level) {
                        emulate = mmu_set_spte(vcpu, iterator.sptep, dsm_access,
                                               write, level, gfn, pfn, prefault,
                                               map_writable);
                        direct_pte_prefetch(vcpu, iterator.sptep);
                        ++vcpu->stat.pf_fixed;
                        break;
                }

                drop_large_spte(vcpu, iterator.sptep);

                /* If entry is not present, then fill the entry*/
                if (!is_shadow_present_pte(*iterator.sptep)) {
                        u64 base_addr = iterator.addr;

                        base_addr &= PT64_LVL_ADDR_MASK(iterator.level);
                        pseudo_gfn = base_addr >> PAGE_SHIFT;
                        sp = kvm_mmu_get_page(vcpu, pseudo_gfn, iterator.addr,
                                              iterator.level - 1, 1, ACC_ALL);

                        link_shadow_page(vcpu, iterator.sptep, sp);
                }
        }
        return emulate;
}
```
The implementation is divided into two parts. First is writing value to entry at target level. It is done by `mmu_set_spte`. Second is populating a new entry for non-present entry. `kvm_mmu_get_page` is responsible for this.

##### kvm_mmu_get_page

Get the kvm_mmu_page corresponding to gfn. It will try to find the corresponding page table page from vcpu->kvm->arch.mmu_page_hash using the gfn as a key. If the page has been allocated before, just return directly. Otherwise, it needs to be allocated from the cache through kvm_mmu_alloc_page and then added to vcpu->kvm->arch.mmu_page_hash with gfn as the key.

To add a new page, we need a data structure `kvm_mmu_page`.
```C
arch/x86/include/asm/kvm_host.h

struct kvm_mmu_page {
        ...
        struct hlist_node hash_link;

        /*
         * The following two entries are used to key the shadow page in the
         * hash table.
         */
        gfn_t gfn;
        union kvm_mmu_page_role role;

        u64 *spt;
        /* hold the gfn of each spte inside spt */
        gfn_t *gfns;
        ...

        struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */

        /* The page is obsolete if mmu_valid_gen != kvm->arch.mmu_valid_gen.  */
        unsigned long mmu_valid_gen;
};
```

hash_link is used as a link for hash list and spt point the allocated page. Also allocated page's page descriptor point to kvm_mmu_page. The overview of the data structure is shown in the figure below.
![hash](hash.png)

```C
arch/x86/kvm/mmu.c

static struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
                                             gfn_t gfn,
                                             gva_t gaddr,
                                             unsigned level,
                                             int direct,
                                             unsigned access)
{
        struct kvm_mmu_page *sp;
        ...
        /* Iterate hash list */
        for_each_valid_sp(vcpu->kvm, sp, gfn) {
                if (sp->gfn != gfn) {
                        collisions++;
                        continue;
                }

                ...
                /* Found the page that existed */
                goto out;
        }
        /* Allocat new kvm_mmu_page */
        ++vcpu->kvm->stat.mmu_cache_miss;

        sp = kvm_mmu_alloc_page(vcpu, direct);

        sp->gfn = gfn;
        sp->role = role;
        hlist_add_head(&sp->hash_link,
                &vcpu->kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)]);
        sp->mmu_valid_gen = vcpu->kvm->arch.mmu_valid_gen;
        clear_page(sp->spt);

        ...

        return sp;
}
```
In the implementation, function iterates the hashlist and check whether that page alread exist. If not allocate a `kvm_mmu_page` and insert it into the hashlist.

kvm_mmu_alloc_page will allocate `kvm_mmu_page` and page objects from vcpu->arch.mmu_page_header_cache and vcpu->arch.mmu_page_cache through mmu_memory_cache_alloc. In mmu_topup_memory_caches, these global variables are guaranteed to be sufficient. If the slab is found to be insufficient, it will be supplemented Also mentioned earlier.

##### link_shadow_page
As mentioned earlier, There is a ramp, which makes it easy to find gfn from HPA. To implemnt reverse-mapping, `kvm_mmu_page` is used. In most cases, gfn corresponds to a single kvm_mmu_page, so rmap_head directly points to spetp. However, since one gfn corresponds to multiple kvm_mmu_pages, in this case, rmap uses linked `pte_list_desc`(list + array) to maintain. It can store three spetp. Since pte_list_desc is frequently allocated, it is also allocated from the cache (vcpu->arch.mmu_pte_list_desc_cache).

```C
arch/x86/kvm/mmu.c

struct pte_list_desc {
        u64 *sptes[PTE_LIST_EXT];
        struct pte_list_desc *more;
};
```
One `pte_list_desc` can store parent entries as much as PTE_LIST_EXT. When it is fulled, KVM make a new `pte_list_des` and link each other using the more member. The connection relationship of the approximate data structure is shown in the picture below.
![rmap](./rmap.png)

```C
arch/x86/kvm/mmu.c

static void link_shadow_page(struct kvm_vcpu *vcpu, u64 *sptep,
                             struct kvm_mmu_page *sp)
{
        u64 spte;

        spte = __pa(sp->spt) | shadow_present_mask | PT_WRITABLE_MASK |
               shadow_user_mask | shadow_x_mask | shadow_me_mask;

        if (sp_ad_disabled(sp))
                spte |= shadow_acc_track_value;
        else
                spte |= shadow_accessed_mask;

        /*  Set the HPA of the next-level page table page */
        mmu_spte_set(sptep, spte);

        /* Add the address of the current item (spetp) to the parent_ptes of the next page table page, and do reverse mapping */
        mmu_page_add_parent_pte(vcpu, sp, sptep);

        ...
}
```


##### mmu_set_spt
Responsible for setting the value of pte(*spetp) in the last-level page table. Also, add the address of the current item (spetp) to `kvm_rmap_head` for a reverse mapping.

```C
static int mmu_set_spte(struct kvm_vcpu *vcpu, u64 *sptep, unsigned pte_access,
                        int write_fault, int level, gfn_t gfn, kvm_pfn_t pfn,
                        bool speculative, bool host_writable)
{
        int was_rmapped = 0;
        int rmap_count;
        int ret = RET_PF_RETRY;
        ...

        /* Set physical page (pfn) starting HPA to *sptep, that is, set the value of a pte in the last-level page table
         * => set_spte
         *   => mmu_spte_update
         *     => mmu_spte_set
         *       => __set_spte
         */
        if (set_spte(vcpu, sptep, pte_access, level, gfn, pfn, speculative,
              true, host_writable)) {
                if (write_fault)
                        ret = RET_PF_EMULATE;
                kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
        }
        ...

        if (is_shadow_present_pte(*sptep)) {
                if (!was_rmapped) {
                        /*
                         * => rmap_add
                         *   => page_header(__pa(spte)): Get the page table page where spetp is located
                         *   => kvm_mmu_page_set_gfn: set gfn to the gfns of the page table page
                         *   => gfn_to_rmap
                         *   => pte_list_add: adds the address of the current item (spetp) to rmap for reverse mapping
                         */
                        rmap_count = rmap_add(vcpu, sptep, gfn);
                        if (rmap_count > RMAP_RECYCLE_THRESHOLD)
                                rmap_recycle(vcpu, sptep, gfn);
                }
        }
        ...
}
```





## Summarize

### QEMU
Create a series of MemoryRegion, respectively representing the ROM, RAM and other areas in the Guest. MemoryRegion maintains the relationship between each other through alias or subregion, so as to further refine the definition of the region.

For an entity MemoryRegion (non-alias), its corresponding RAMBlock will be created during the process of initializing the memory. RAMBlock allocates memory from the process space of QEMU through mmap, and is responsible for maintaining the starting HVA/GPA/size information of the MemoryRegion management memory.

AddressSpace represents the physical address space of the VM. If the MemoryRegion in the AddressSpace changes, the listener is triggered to flatten the MemoryRegion tree of the AddressSpace to which it belongs to form a one-dimensional FlatView, and compare whether the FlatRange has changed. If it is to call the corresponding method such as region_add to check the changed section region, update the KVMSlot in QEMU, and fill in the kvm_userspace_memory_region structure at the same time, update the kvm_memory_slot in KVM as an ioctl parameter.

### KVM
When QEMU creates vcpu through ioctl, it calls kvm_mmu_create to initialize mmu related information and allocates slab cache for the page table entry structure.

Before KVM enters the guest, vcpu_enter_guest => kvm_mmu_reload will load the root-level page table address into the VMCS and let the guest use the page table.

When EPT Violation occurs, VMEXIT is triggered. To handle this, get the corresponding GPA, calculate the gfn according to the GPA, find the corresponding memory slot according to the gfn, and get the corresponding HVA. Then find the corresponding pfn according to the HVA and make sure that the page is in the memory. After filling in the missing pages, the EPT needs to be updated to complete the missing page table entries. So starting from L4, the page table is completed level by level. For the page table pages that are missing on a certain level, the HPA of the new page will be filled into the upper level page table after being allocated from the slab.

In addition to establishing the association between the upper-level page table and the lower-level page table, KVM will also establish a reverse mapping, which can directly find the gfn-related page table entries based on the GPA without having to go through the EPT query again.
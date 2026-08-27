// Forcibly mode-switch a Realtek RTL88xxCU dongle out of CD-ROM mode
// (0bda:1a2b) on macOS by SEIZING the mass-storage interface away from the
// kernel driver via IOKit's USBInterfaceOpenSeize — something libusb cannot do
// (libusb uses plain USBInterfaceOpen, which fails when a driver owns the
// interface). Then send the SCSI START STOP UNIT (LOEJ) eject CBW that triggers
// the Realtek switch to WiFi mode (0bda:c811/c820).
//
// Build: clang -o modeswitch_seize modeswitch_seize.c -framework IOKit -framework CoreFoundation
// Run:   sudo ./modeswitch_seize
#include <stdio.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <mach/mach.h>

#define VID 0x0bda
#define PID 0x1a2b

// Find the mass-storage *interface* IOService of the 0bda:1a2b device directly,
// without opening the device user client (which the kernel driver holds with
// exclusive access). We match IOUSBHostInterface nodes and check the parent
// device's idVendor/idProduct.
static io_service_t find_interface(void) {
    const char *classes[] = {"IOUSBHostInterface", "IOUSBInterface"};
    for (int c = 0; c < 2; c++) {
        CFMutableDictionaryRef m = IOServiceMatching(classes[c]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS) continue;
        io_service_t s;
        while ((s = IOIteratorNext(it))) {
            int vid = 0, pid = 0;
            CFTypeRef vr = IORegistryEntrySearchCFProperty(s, kIOServicePlane, CFSTR("idVendor"),
                NULL, kIORegistryIterateParents | kIORegistryIterateRecursively);
            CFTypeRef pr = IORegistryEntrySearchCFProperty(s, kIOServicePlane, CFSTR("idProduct"),
                NULL, kIORegistryIterateParents | kIORegistryIterateRecursively);
            if (vr) { CFNumberGetValue(vr, kCFNumberIntType, &vid); CFRelease(vr); }
            if (pr) { CFNumberGetValue(pr, kCFNumberIntType, &pid); CFRelease(pr); }
            if (vid == VID && pid == PID) {
                IOObjectRelease(it);
                printf("matched 0bda:1a2b interface via %s\n", classes[c]);
                return s;
            }
            IOObjectRelease(s);
        }
        IOObjectRelease(it);
    }
    return 0;
}

int main(void) {
    io_service_t intf_svc = find_interface();
    if (!intf_svc) { printf("no 0bda:1a2b interface found (is the dongle plugged in?)\n"); return 1; }

    IOCFPlugInInterface **ip = NULL; SInt32 sc = 0;
    kern_return_t pkr = IOCreatePlugInInterfaceForService(intf_svc,
            kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &ip, &sc);
    if (pkr != KERN_SUCCESS || !ip) {
        printf("IOCreatePlugInInterfaceForService(interface) failed: 0x%08x "
               "(0xe00002c5=need sudo; 0xe00002be=exclusive access held by kernel)\n", pkr);
        IOObjectRelease(intf_svc); return 1;
    }
    IOUSBInterfaceInterface **intf = NULL;
    (*ip)->QueryInterface(ip, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&intf);
    (*ip)->Release(ip);
    IOObjectRelease(intf_svc);
    if (!intf) { printf("QueryInterface(interface) failed\n"); return 1; }

    // SEIZE the interface away from the mass-storage kernel driver.
    kern_return_t kr = (*intf)->USBInterfaceOpenSeize(intf);
    printf("USBInterfaceOpenSeize: 0x%08x %s\n", kr,
           kr ? "(could not seize — 0xe00002c5=need sudo, 0xe00002be=exclusive)"
              : "(SEIZED from kernel driver!)");
    if (kr != KERN_SUCCESS) { (*intf)->Release(intf); return 1; }

    int switched = 0;
    UInt8 nep = 0; (*intf)->GetNumEndpoints(intf, &nep);
    UInt8 outPipe = 0;
    for (UInt8 i = 1; i <= nep; i++) {
        UInt8 dir = 0, num = 0, tt = 0, interval = 0; UInt16 mps = 0;
        (*intf)->GetPipeProperties(intf, i, &dir, &num, &tt, &mps, &interval);
        if (tt == kUSBBulk && dir == kUSBOut) outPipe = i;
    }
    if (outPipe) {
        unsigned char cbw[31] = {0};
        memcpy(cbw, "USBC", 4);
        cbw[4] = 0x78; cbw[5] = 0x56; cbw[6] = 0x34; cbw[7] = 0x12; // tag
        cbw[14] = 6;     // CB length
        cbw[15] = 0x1b;  // SCSI START STOP UNIT
        cbw[19] = 0x02;  // LOEJ=1 -> eject
        kr = (*intf)->WritePipe(intf, outPipe, cbw, sizeof(cbw));
        printf("WritePipe eject CBW (pipe %d): 0x%08x %s\n", outPipe, kr,
               kr ? "(write failed)" : "(EJECT SENT)");
        if (kr == KERN_SUCCESS) switched = 1;
    } else {
        printf("no bulk-OUT pipe found on the seized interface\n");
    }
    (*intf)->USBInterfaceClose(intf);
    (*intf)->Release(intf);

    printf(switched ? "\ndone — re-check usb_list in a few seconds for 0bda:c811/c820.\n"
                    : "\nno eject sent.\n");
    return switched ? 0 : 1;
}

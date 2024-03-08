//
//  hook_entry.cpp
//  test_game
//
//  Created by 尹海晶 on 2024/3/8.
//

#include "hook_entry.hpp"
#import <UIKit/UIKit.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
//#import <objc/runtime.h>
//#import <objc/message.h>
#import "fishhook.h"
#include "helloworld.h"
#include "dobby.h"
 
static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);
 
int my_close(int fd) {
  printf("Calling real close(%d)\n", fd);
  return orig_close(fd);
}
 
int my_open(const char *path, int oflag, ...) {
  va_list ap = {0};
  mode_t mode = 0;
 
  if ((oflag & O_CREAT) != 0) {
    // mode only applies to O_CREAT
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
    printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
    return orig_open(path, oflag, mode);
  } else {
    printf("Calling real open('%s', %d)\n", path, oflag);
    return orig_open(path, oflag, mode);
  }
}


void printAppPathAndName() {
    // 获取应用程序的主bundle
    NSBundle *mainBundle = [NSBundle mainBundle];

    // 获取应用程序的路径
    NSString *appPath = [mainBundle bundlePath];

    // 获取应用程序的名称
    NSString *appName = [mainBundle objectForInfoDictionaryKey:@"CFBundleName"];

    // 使用NSLog打印路径和名称
    NSLog(@"Application Path: %@", appPath);
    NSLog(@"Application Name: %@", appName);
}


 
void get_all_image_of_app()
{
        uint32_t count = (uint32_t)_dyld_image_count();
        for(uint32_t i = 0; i < count; i++){
            char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
            long slide = (long)_dyld_get_image_vmaddr_slide(i);
            uintptr_t baseAddr = (uintptr_t)_dyld_get_image_header(i);
            NSString* curModuleName = @(curModuleName_cstr);
            printf("module name:%s\n",curModuleName_cstr);
        }
}

void printMainBundleExecutablePath() {
    NSString *executablePath = [[NSBundle mainBundle] executablePath];
    NSLog(@"Executable Path: %@", executablePath);
}

/*
void get_main_image_path()
{
    // 使用objc_msgSend获取主bundle
    id (*objc_msgSendTyped)(id self, SEL _cmd) = (void *)objc_msgSend;
    
    id bundle = objc_msgSendTyped(objc_getClass("NSBundle"), sel_registerName("mainBundle"));
    
    // 使用objc_msgSend获取可执行文件路径
    id (*objc_msgSendTypedPath)(id self, SEL _cmd) = (void *)objc_msgSend;
    
    id exePath = objc_msgSendTypedPath(bundle, sel_registerName("executablePath"));
    
    // 使用objc_msgSend获取路径的UTF8字符串
    const char *(*objc_msgSendTypedUTF8)(id self, SEL _cmd) = (void *)objc_msgSend;
    
    const char *path = objc_msgSendTypedUTF8(exePath, sel_registerName("UTF8String"));
    
    // 打印路径
    printf("image path: %s\n", path);
}
*/

void  get_module_base_addr_by_name(char* moduleName_cstr)
{
    // 使用UTF-8编码将char*转换为NSString对象
    NSString *moduleName = [NSString stringWithCString:moduleName_cstr encoding:NSUTF8StringEncoding];
    uint32_t count = (uint32_t)_dyld_image_count();
    for(uint32_t i = 0; i < count; i++){
        char* curModuleName_cstr = (char*)_dyld_get_image_name(i);
        long slide = (long)_dyld_get_image_vmaddr_slide(i);
        uintptr_t baseAddr = (uintptr_t)_dyld_get_image_header(i);
        NSString* curModuleName = @(curModuleName_cstr);
        if([curModuleName containsString:moduleName]) {
            printf("get_module_base_addr_by_name , base:%ld,slide:%ld,\n", baseAddr,slide);
        }
    }
}

void get_func_info_by_name(const char * funcName_cstr)
{
    NSMutableString* retStr = [NSMutableString string];
    /*
    #define RTLD_LAZY   0x1
    #define RTLD_NOW    0x2
    #define RTLD_LOCAL  0x4
    #define RTLD_GLOBAL 0x8
     */
  //  typedef struct dl_info {
 //       const char      *dli_fname;     /* Pathname of shared object */
//        void            *dli_fbase;     /* Base address of shared object */
//        const char      *dli_sname;     /* Name of nearest symbol */
//        void            *dli_saddr;     /* Address of nearest symbol */
 //   } Dl_info;
    
    Dl_info dl_info;
    void* handle = (void*)dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    if(handle == nil)
    {
        [retStr appendString:@"[-] handle is  null"];
    }
    void* target_ptr = (void*)dlsym(handle, funcName_cstr);
    
    if(target_ptr){
        uintptr_t target_addr = (uintptr_t)target_ptr;
        
        dladdr(target_ptr, &dl_info);
        
        char* module_path = (char*)dl_info.dli_fname;
        uintptr_t module_base = (uintptr_t)dl_info.dli_fbase;
        char* symbol_name = (char*)dl_info.dli_sname;
        uintptr_t symbol_addr = (uintptr_t)dl_info.dli_saddr;
        uintptr_t offset = (uintptr_t)(target_addr -module_base);
        
        [retStr appendString:@"Func   name: "];
        [retStr appendString:@((char*)funcName_cstr)];
        [retStr appendString:@"\nFunc   addr: "];
        [retStr appendString:(id)[@(target_addr) stringValue]];
        
        [retStr appendString:@"\nModule Path: "];
        [retStr appendString:@(module_path)];
        [retStr appendString:@"\nModule base: "];
        [retStr appendString:(id)[@(module_base) stringValue]];
        [retStr appendString:@"\nSymbol name: "];
        [retStr appendString:@(symbol_name)];
        [retStr appendString:@"\nSymbol addr: "];
        [retStr appendString:(id)[@(symbol_addr) stringValue]];
        
        [retStr appendString:@"\nOffset : "];
        [retStr appendString:(id)[@(offset) stringValue]];
    }else{
        [retStr appendString:@"[-] dlsym not found symbol:"];
        [retStr appendString:@((char*)funcName_cstr)];
    }
    NSLog(@"symbol info :%@", retStr);
}


void HooKEntry::execute()
{
    //printAppPathAndName();
    //get_all_image_of_app();
   //get_main_image_path();
    get_func_info_by_name("objc_alloc_init");
    
    /*
    void* handle = dlopen(NULL, RTLD_NOW); // 加载当前进程
    void* addr = dlsym(handle, "my_open"); // 查找符号地址
    //dlclose(handle); // 关闭库
    void* test_addr = (void*)&my_open;
    
    printf("addr:%p, test_addr:%p\n", addr, test_addr);
    
    @autoreleasepool {
    
        
      rebind_symbols((struct rebinding[2]){{"close", (void*)my_close, (void **)&orig_close}, {"open", addr, (void **)&orig_open}}, 2);
   
      // Open our own binary and print out first 4 bytes (which is the same
      // for all Mach-O binaries on a given architecture)
      int fd = open(argv[0], O_RDONLY);
      uint32_t magic_number = 0;
      read(fd, &magic_number, 4);
      printf("Mach-O Magic Number: %x \n", magic_number);
      close(fd);
    }
    */
    int ret =  DobbyHook((void*)close, (void*)my_close, (void **)&orig_close);
     ret = DobbyHook((void*)open, (void*)my_open,(void **)&orig_open);
    int fd = open("test_file", O_RDONLY);
    uint32_t magic_number = 0;
    read(fd, &magic_number, 4);
    printf("Mach-O Magic Number: %x \n", magic_number);
    close(fd);
}

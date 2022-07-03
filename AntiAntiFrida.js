/*
   Made By @ApkUnpacker on 29/06/2022
   Uploaded on 03/07/2022(so i can remember that i faced 4 days internet ban in my area and in free time made this, lol)
   Updated by @KingMahmud on 03/07/2022
*/

const library_name = "libxyz.so";

const libc = Process.getModuleByName("libc.so");
const find = (exp) => libc.findExportByName(exp);

const pthread_create_ptr = find("pthread_create");
const pthread_create = new NativeFunction(pthread_create_ptr, "int", ["pointer", "pointer", "pointer", "pointer"]);
const open_ptr = find("open");
const open = new NativeFunction(open_ptr, "int", ["pointer", "int"]);
const read_ptr = find("read");
const read = new NativeFunction(read_ptr, "int", ["int", "pointer", "int"]);
const close_ptr = find("close");
const close = new NativeFunction(close_ptr, "int", ["int"]);
const inet_aton_ptr = find("inet_aton");
const inet_aton = new NativeFunction(inet_aton_ptr, "int", ["pointer", "pointer"]);
const popen_ptr = find("popen");
const popen = new NativeFunction(popen_ptr, "pointer", ["pointer", "pointer"]);
const symlink_ptr = find("symlink");
const symlink = new NativeFunction(symlink_ptr, "int", ["pointer", "pointer"]);
const symlinkat_ptr = find("symlinkat");
const symlinkat = new NativeFunction(symlinkat_ptr, "int", ["pointer", "int", "pointer"]);
const inet_addr_ptr = find("inet_addr");
const inet_addr = new NativeFunction(inet_addr_ptr, "int", ["pointer"]);
const socket_ptr = find("socket");
const socket = new NativeFunction(socket_ptr, "int", ["int", "int", "int"]);
const connect_ptr = find("connect");
const connect = new NativeFunction(connect_ptr, "int", ["int", "pointer", "int"]);
const send_ptr = find("send");
// clash with frida send, append _
const send_ = new NativeFunction(send_ptr, "int", ["int", "pointer", "int", "int"]);
const sendto_ptr = find("sendto");
const sendto = new NativeFunction(sendto_ptr, "int", ["int", "pointer", "int", "int", "pointer", "int"]);
const fgets_ptr = find("fgets");
const fgets = new NativeFunction(fgets_ptr, "pointer", ["pointer", "int", "pointer"]);
const readlink_ptr = find("readlink");
const readlink = new NativeFunction(readlink_ptr, "int", ["pointer", "pointer", "int"]);
const readlinkat_ptr = find("readlinkat");
const readlinkat = new NativeFunction(readlinkat_ptr, "int", ["int", "pointer", "pointer", "int"]);
const memcpy_ptr = find("memcpy");
const memcpy = new NativeFunction(memcpy_ptr, "pointer", ["pointer", "pointer", "int"]);

function getProcessName() {
    const path = Memory.allocUtf8String("/proc/self/cmdline");
    const fd = open(path, 0);
    if (fd != -1) { // TODO : Find out if fd != -1 or fd !== -1 is efficient.
        const buffer = Memory.alloc(0x1000);
        const result = read(fd, buffer, 0x1000);
        close(fd);
        return ptr(buffer).readCString();
    }
    return "";
}

const process_name = getProcessName();

Interceptor.replace(pthread_create_ptr, new NativeCallback(function(ptr0, ptr1, ptr2, ptr3) {
    const lib_base = Module.findBaseAddress(library_name);
    const ptr0_name = getModuleNameFromAddress(ptr0);
    if (ptr0_name == library_name) {
        console.log("Thread created ptr0 : ", ptr0_name, lib_base, ptr0.sub(lib_base));
    }
    const ptr1_name = getModuleNameFromAddress(ptr1);
    if (ptr1_name == library_name) {
        console.log("Thread created ptr1 : ", ptr1_name, lib_base, ptr1.sub(lib_base));
        Interceptor.attach(lib_base.add(ptr1.sub(lib_base)), {
            onEnter: function(args) {
                console.log("New thread func", ptr1.sub(lib_base), "args : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New thread func return : ", retval);
            }
        });
    }
    const ptr2_name = getModuleNameFromAddress(ptr2);
    if (ptr2_name == library_name) {
        console.log("Thread created ptr2 : ", ptr2_name, lib_base, ptr2.sub(lib_base));
        Interceptor.attach(lib_base.add(ptr2.sub(lib_base)), {
            onEnter: function(args) {
                console.log("New thread func", ptr2.sub(lib_base), "args : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New thread func return : ", retval);
            }
        });
    }
    const ptr3_name = getModuleNameFromAddress(ptr3);
    if (ptr3_name == library_name) {
        console.log("Thread created ptr3 : ", ptr3_name, lib_base, ptr3.sub(lib_base));
        Interceptor.attach(lib_base.add(ptr3.sub(lib_base)), {
            onEnter: function(args) {
                console.log("New thread func", ptr3.sub(lib_base), "args : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New thread func return : ", retval);
            }
        });
    }
    if (ptr1.isNull() && ptr3.isNull()) {
        console.warn("loading fake pthread_create");
        /* return -1 if you not want to create that thread */
        return pthread_create(ptr0, ptr1, ptr2, ptr3);
        // return -1;
    } else {
        return pthread_create(ptr0, ptr1, ptr2, ptr3);
    }
}, "int", ["pointer", "pointer", "pointer", "pointer"]));

function getModuleNameFromAddress(addr) {
    if (addr !== null && !addr.isNull()) {
        try {
            return Process.getModuleByAddress(addr).name;
        } catch (e) {
            // console.error(e);
            return "";
        }
    }
}

// Few methods might check frida's presence so added them if process freeze you can comment these

Interceptor.replace(inet_aton_ptr, new NativeCallback(function(addrs, structure) {
    const retval = inet_aton(addrs, structure);
    console.log("inet_aton : ", addrs.readCString());
    return retval;
}, "int", ["pointer", "pointer"]));

Interceptor.replace(popen_ptr, new NativeCallback(function(path, type) {
    const retval = popen(path, type);
    console.log("popen : ", path.readCString());
    return retval;
}, "pointer", ["pointer", "pointer"]));

Interceptor.replace(symlink_ptr, new NativeCallback(function(target, path) {
    const retval = symlink(target, path);
    console.log("symlink: ", target.readCString(), path.readCString());
    return retval;
}, "int", ["pointer", "pointer"]));

Interceptor.replace(symlinkat_ptr, new NativeCallback(function(target, fd, path) {
    const retval = symlinkat(target, fd, path);
    console.log("symlinkat : ", target.readCString(), path.readCString());
    return retval;
}, "int", ["pointer", "int", "pointer"]));

Interceptor.replace(inet_addr_ptr, new NativeCallback(function(path) {
    const retval = inet_addr(path);
    console.log("inet_addr : ", path.readCString())
    return retval;
}, "int", ["pointer"]));

Interceptor.replace(socket_ptr, new NativeCallback(function(domain, type, proto) {
    const retval = socket(domain, type, proto);
    console.warn("socket  : ", domain, type, proto, "Return : ", retval)
    return retval;
}, "int", ["int", "int", "int"]));

Interceptor.replace(connect_ptr, new NativeCallback(function(fd, addr, len) {
    const retval = connect(fd, addr, len);
    const family = addr.readU16();
    let port = addr.add(2).readU16();
    // port = ((port & 0xff) << 8) | (port >> 8);
    console.warn("Connect : ", family, "Port : ", port, "Return : ", retval);
    return retval;
}, "int", ["int", "pointer", "int"]));

Interceptor.replace(send_ptr, new NativeCallback(function(socksfd, msg, slen, flag, daddr, dlen) {
    const retval = send_(socksfd, msg, slen, flag);
    console.log("send : ", socksfd, msg.readCString(), slen, flag);
    return retval;
}, "int", ["int", "pointer", "int", "int"]));

Interceptor.replace(sendto_ptr, new NativeCallback(function(socksfd, msg, slen, flag, daddr, dlen) {
    const retval = sendto(socksfd, msg, slen, flag, daddr, dlen);
    // console.log("sendto : ", socksfd, msg.readCString(), slen, flag, daddr, dlen);
    return retval;
}, "int", ["int", "pointer", "int", "int", "pointer", "int"]));

// if process name not work correctly you can replace manually with your package name here

console.log(process_name);

const fake_maps = "/data/data/" + process_name + "/maps";
const fake_task = "/data/data/" + process_name + "/task";
const fake_exe = "/data/data/" + process_name + "/exe";
const fake_mounts = "/data/data/" + process_name + "/mounts";
const fake_status = "/data/data/" + process_name + "/status";

const maps = new File(fake_maps, "w");
const task = new File(fake_task, "w");
const exe = new File(fake_exe, "w");
const mounts = new File(fake_mounts, "w");
const status = new File(fake_status, "w");

const maps_buf = Memory.alloc(512);
const task_buf = Memory.alloc(512);
const exe_buf = Memory.alloc(512);
const mounts_buf = Memory.alloc(512);
const status_buf = Memory.alloc(512);

// const map_open64_buf = Memory.alloc(512);

const detection_strs = [
    "/data/local/tmp/re.frida.server/frida-agent-64.so",
    "re.frida.server",
    "re.frida",
    // "re."
    "frida.",
    "frida-agent",
    "frida-agent-64.so",
    "rida-agent-64.so",
    "agent-64.so",
    "frida-agent-32.so",
    "frida-helper-32",
    "frida-helper",
    "pool-frida",
    "frida",
    "frida-",
    // "/data/local/tmp",
    "server",
    "frida-server",
    "linjector",
    "gum-js-loop",
    "frida_agent_main",
    "gmain",
    "magisk",
    ".magisk",
    "/sbin/.magisk",
    "libriru",
    "xposed",
    "system_root",
    "mirror"
];

Interceptor.replace(open_ptr, new NativeCallback(function(pathname, flag) {
    const fd = open(pathname, flag);
    const path = pathname.readCString();
    /*
    if (path.includes("lib") && path.includes(".so")) {
        return fd;
    }
    */
    if (path.includes("/data/local/tmp")) {
        return -1;
    }
    if (path.includes("/proc/")) {
        if (path.includes("maps")) {
            console.log("open : ", path);
            while (parseInt(read(fd, maps_buf, 512)) !== 0) {
                let buffer = maps_buf.readCString()
                detection_strs.forEach(str => {
                    buffer = buffer.replaceAll(str, "FakingMaps");
                });
                maps.write(buffer);
                // console.log("buffer : ", buffer);                                     
            }
            return open(Memory.allocUtf8String(fake_maps), flag);
        } else if (path.includes("task")) {
            console.log("open : ", path);
            while (parseInt(read(fd, task_buf, 512)) !== 0) {
                let buffer = task_buf.readCString()
                detection_strs.forEach(str => {
                    buffer = buffer.replaceAll(str, "StaySafeStayHappy");
                });
                task.write(buffer);
                // console.log(buffer);
            }
            return open(Memory.allocUtf8String(fake_task), flag);
        } else if (path.includes("exe")) {
            console.log("open : ", path);
            while (parseInt(read(fd, exe_buf, 512)) !== 0) {
                let buffer = exe_buf.readCString();
                detection_strs.forEach(str => {
                    buffer = buffer.replaceAll(str, "StaySafeStayHappy");
                });
                // console.warn(buffer)
                exe.write(buffer);
            }
            return open(Memory.allocUtf8String(fake_exe), flag);
        } else if (path.includes("mounts")) {
            console.log("open : ", path);
            while (parseInt(read(fd, mounts_buf, 512)) !== 0) {
                let buffer = mounts_buf.readCString()
                detection_strs.forEach(str => {
                    buffer = buffer.replaceAll(str, "StaySafeStayHappy");
                });
                mounts.write(buffer);
                // console.log("buffer : ", buffer);                                     
            }
            return open(Memory.allocUtf8String(fake_mounts), flag);
        }
        /*
        else if (path.includes("status")) {
            console.log("open : ", path);
            while (parseInt(read(fd, status_buf, 512)) !== 0) {
                const PStatus = status_buf.readCString();
                if (PStatus.includes("TracerPid:")) {
                    open_buf.writeUtf8String("TracerPid:\t0");
                    console.log("Bypassing TracerPID Check");
                }
                status.write(PStatus);
            }
            return open(Memory.allocUtf8String(fake_status), flag);
        }
        */
        else {
            return fd;
        }
    }
    return fd;
}, "int", ["pointer", "int"]));

Interceptor.replace(fgets_ptr, new NativeCallback(function(buf, size, fp) {
    // const retval = fgets(buf, size, fp);
    let buffer = buf.readCString();
    detection_strs.forEach(str => {
        buffer = buffer.replaceAll(str, "FakingGets");
    });
    buf.writeUtf8String(buffer);
    // console.log(buf.readCString());
    return fgets(buf, size, fp);
    // return retval;
}, "pointer", ["pointer", "int", "pointer"]));

Interceptor.replace(readlink_ptr, new NativeCallback(function(pathname, buffer, bufsize) {
    const retval = readlink(pathname, buffer, bufsize);
    const str = buffer.readCString();
    if (detection_strs.some(frida => str.includes(frida))) {
        console.log(str, "Check in readlink");
        buffer.writeUtf8String("/system/framework/services.jar");
        return readlink(pathname, buffer, bufsize);
    }
    // console.log("readlink : ", pathname.readCString(), str);
    return retval;
}, "int", ["pointer", "pointer", "int"]))

Interceptor.replace(readlinkat_ptr, new NativeCallback(function(dirfd, pathname, buffer, bufsize) {
    const retval = readlinkat(dirfd, pathname, buffer, bufsize);
    const str = buffer.readCString();
    if (detection_strs.some(frida => str.includes(frida))) {
        console.log(str, "Check in readlinkat");
        buffer.writeUtf8String("/system/framework/services.jar");
        return readlinkat(dirfd, pathname, buffer, bufsize);
    }
    // console.log("readlinkat : ", pathname.readCString(), str);
    return retval;
}, "int", ["int", "pointer", "pointer", "int"]))

Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter: function(args) {
        this.frida = false;
        const str1 = args[0].readCString();
        const str2 = args[1].readCString();
        if (detection_strs.some(frida => str1.includes(frida) || str2.includes(frida))) {
            this.frida = true;
            console.log("strstr : ", str1, str2);
        }
    },
    onLeave: function(retval) {
        if (this.frida) {
            retval.replace(ptr(0));
        }
    }
});


// Enabling it might give crash on some apps 
/*

Interceptor.attach(read_ptr, {
    onEnter: function(args) {
        try {
            let buffer = args[1].readCString();
            detection_strs.forEach(str => {
                buffer = buffer.replaceAll(str, "StaySafeStayHappy");
            });
            args[1].writeUtf8String(buffer);
        }
    } catch (e) {
        // console.error(e);
    }
});

// TODO : Rethink the necessity of this
if (Process.arch.includes("64")) {
    const open64_ptr = find("open64");
    const open64 = new NativeFunction(open64_ptr, "int", ["pointer", "int"]);
    Interceptor.replace(open64_ptr, new NativeCallback(function(pathname, flag) {
        const fd = open64(pathname, flag);
        const path = pathname.readCString();
        if (path.includes("/proc/")) {
            if (path.includes("maps")) {
                // console.log("open64 : ", pathname.readCString()) 
                while (parseInt(read(fd, map_open64_buf, 512)) !== 0) {
                    let buffer = maps_open64_buf.readCString();
                    detection_strs.forEach(str => {
                        buffer = buffer.replaceAll(str, "FakingMaps");
                    });
                    maps.write(buffer);
                    // console.log("buffer : ", buffer);
                }
                return open64(Memory.allocUtf8String(fake_maps), flag);
            }
        }
        return fd;
    }, "int", ["pointer", "int"]));
}

Interceptor.replace(memcpy_ptr, new NativeCallback(function(dest, src, len) {
    const retval = memcpy(dest, src, len);
    const str1 = dest.readCString();
    const str2 = src.readCString();
    if (str1 != null && str2 != null && (str1.includes("frida") || str2.includes("frida"))) {
        // console.warn("memcpy : ", str1, str2);
        const buffer = str1;
        detection_strs.forEach(str => {
            buffer = buffer.replaceAll(str, "StaySafeStayHappy");
        });
        const buffer2 = str2;
        detection_strs.forEach(str => {
            buffer2 = buffer2.replaceAll(str, "StaySafeStayHappy");
        });
        dest.writeUtf8String(buffer);
        src.writeUtf8String(buffer2);
        // console.log(buffer, buffer2);
        return memcpy(dest, src, len);
    }
    return retval;
}, "pointer", ["pointer", "pointer", "int"]));

*/
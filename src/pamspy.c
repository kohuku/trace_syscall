#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "pamspy.skel.h"
#include "pamspy_symbol.h"
#include "pamspy_event.h"

const char header[] =
"**************************************************************\n"
"*           / __ \\/ __ `/ __ `__ \\/ ___/ __ \\/ / / /         *\n"
"*          / /_/ / /_/ / / / / / (__  ) /_/ / /_/ /          *\n"
"*         / .___/\\__,_/_/ /_/ /_/____/ .___/\\__, /           *\n"
"*        /_/                        /_/    /____/            *\n"
"*                               by @citronneur (v0.2)        *\n"
"**************************************************************\n";


const char *argp_program_version = "pamspy 1.0";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"pamspy\n"
"\n"
"Uses eBPF to dump secrets use by PAM (Authentication) module\n"
"By hooking the pam_get_authtok function in libpam.so\n"
"\n"
"USAGE: ./pamspy -p $(/usr/sbin/ldconfig -p | grep libpam.so | cut -d ' ' -f4) -d /var/log/trace.0\n";

/******************************************************************************/
/*!
 *  \brief   arguments
 */
static struct env {
    int verbose;    // will print more details of the execution
    int print_headers;
    char* libpam_path;
    char* output_path;
} env;

/******************************************************************************/
static const struct argp_option opts[] = {
    { "path", 'p', "PATH", 0, "Path to the libpam.so file" },
    { "daemon", 'd', "OUTPUT", 0, "Start pamspy in daemon mode and output in the file passed as argument" },
    { "verbose", 'v', NULL, 1, "Verbose mode" },
    { "print-headers", 'r', NULL, 1, "Print headers of the program" },
    {},
};

/******************************************************************************/
/*!
 *  \brief  use to manage exit of the infinite loop
 */
static volatile sig_atomic_t exiting;

/******************************************************************************/
/*!
 *  signal handler
 */
void sig_int(int signo)
{
    exiting = 1;
}

/******************************************************************************/
/*!
 * \brief   print debug informations of libbpf
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/******************************************************************************/
/*!
 *  \brief  parse arguments of the command line
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.libpam_path = strdup(arg);
        break;
    case 'd':
        env.output_path = strdup(arg);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'r':
        env.print_headers = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/******************************************************************************/
// parse args configuration
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/******************************************************************************/
/*!
 *  \brief  each time a secret from ebpf is detected
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    event_t* e = (event_t*)data;
    if (env.output_path != NULL)
    {
        fprintf(stderr, "%u,%d,%d,%d,%d,%d,%d,%d,%d\n", e->pid, e->uid, e->euid, e->suid, e->new_uid, e->new_euid, e->new_suid, e->error_flag, e->syscall_no);
    }
    else
    {
        fprintf(stderr, "%u,%d,%d,%d,%d,%d,%d,%d,%d\n", e->pid, e->uid, e->euid, e->suid, e->new_uid, e->new_euid, e->new_suid, e->error_flag, e->syscall_no);
    }
    return 0;
}

/******************************************************************************/
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = 
    {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) 
    {
        return false;
    }
    return true;
}

/******************************************************************************/
static void start_daemon(void)
{
    pid_t child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    // become the group leader
    setsid();

    child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    umask(0);

    int chdir_flag = chdir("/tmp");
    if (chdir_flag != 0)
    {
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    int fd_0 = open("/dev/null", O_RDWR);
    if (fd_0 != 0)
    {
        exit(1);
    }

    int fd_1 = open(env.output_path, O_RDWR | O_CREAT | O_APPEND, 0600);
    if (fd_1 != 1)
    {
        exit(1);
    }

    int fd_2 = dup(fd_1);
    if (fd_2 != 2)
    {
        exit(1);
    }
}

/******************************************************************************/
int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct pamspy_bpf *skel;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    env.verbose = false;
    env.print_headers = false;
    env.libpam_path = NULL;
    env.output_path = NULL;


    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) 
    {
        return err;
    }

    if(env.libpam_path == NULL) 
    {
        fprintf(stderr, "pamspy: argument PATH is mandatory\n");
        exit(1);
    }

    int offset = pamspy_find_symbol_address(env.libpam_path, "pam_get_authtok");

    if (offset == -1) 
    {
        fprintf(stderr, "pamspy: Unable to find pam_get_authtok function in %s\n", env.libpam_path);
        exit(1);
    }

    // check deamon mode
    if (env.output_path != NULL)
    {
        start_daemon();
    }

    if(env.verbose)
        libbpf_set_print(libbpf_print_fn);


    if(!bump_memlock_rlimit())
    {
        fprintf(stderr, "pamspy: Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        exit(1);
    }
 
    // Open BPF application 
    skel = pamspy_bpf__open();
    if (!skel) {
        fprintf(stderr, "pamspy: Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Load program
    err = pamspy_bpf__load( skel);
    if (err) {
        fprintf(stderr, "pamspy: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    
    // // sys_enter の raw_tracepoint にアタッチ
    // skel->links.trace_enter_allsyscalls = bpf_program__attach_raw_tracepoint(
    //     skel->progs.trace_enter_allsyscalls,  // プログラム名
    //     "sys_enter"  // raw_tracepoint 名
    // );
    // if (!skel->links.trace_enter_allsyscalls) {
    //     fprintf(stderr, "Failed to attach raw tracepoint sys_enter\n");
    //     return -1;
    // }   

    // // sys_exit の raw_tracepoint にアタッチ
    // skel->links.trace_exit_allsyscalls = bpf_program__attach_raw_tracepoint(
    //     skel->progs.trace_exit_allsyscalls,  // プログラム名
    //     "sys_exit"  // raw_tracepoint 名
    // );
    // if (!skel->links.trace_exit_allsyscalls) {
    //     fprintf(stderr, "Failed to attach raw tracepoint sys_exit\n");
    //     return -1;
    // }

    // execve システムコールに対する設定
    skel->links.trace_enter_execve = bpf_program__attach_tracepoint(skel->progs.trace_enter_execve, "syscalls", "sys_enter_execve");
    skel->links.trace_exit_execve = bpf_program__attach_tracepoint(skel->progs.trace_exit_execve, "syscalls", "sys_exit_execve");

    // setuid システムコールに対する設定
    skel->links.trace_enter_setuid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setuid, "syscalls", "sys_enter_setuid");
    skel->links.trace_exit_setuid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setuid, "syscalls", "sys_exit_setuid");

    // setgid システムコールに対する設定
    skel->links.trace_enter_setgid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setgid, "syscalls", "sys_enter_setgid");
    skel->links.trace_exit_setgid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setgid, "syscalls", "sys_exit_setgid");

    // setreuid システムコールに対する設定
    skel->links.trace_enter_setreuid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setreuid, "syscalls", "sys_enter_setreuid");
    skel->links.trace_exit_setreuid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setreuid, "syscalls", "sys_exit_setreuid");

    // setregid システムコールに対する設定
    skel->links.trace_enter_setregid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setregid, "syscalls", "sys_enter_setregid");
    skel->links.trace_exit_setregid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setregid, "syscalls", "sys_exit_setregid");

    // setresuid システムコールに対する設定
    skel->links.trace_enter_setresuid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setresuid, "syscalls", "sys_enter_setresuid");
    skel->links.trace_exit_setresuid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setresuid, "syscalls", "sys_exit_setresuid");

    // setresgid システムコールに対する設定
    skel->links.trace_enter_setresgid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setresgid, "syscalls", "sys_enter_setresgid");
    skel->links.trace_exit_setresgid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setresgid, "syscalls", "sys_exit_setresgid");

    // setfsuid システムコールに対する設定
    skel->links.trace_enter_setfsuid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setfsuid, "syscalls", "sys_enter_setfsuid");
    skel->links.trace_exit_setfsuid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setfsuid, "syscalls", "sys_exit_setfsuid");

    // setfsgid システムコールに対する設定
    skel->links.trace_enter_setfsgid = bpf_program__attach_tracepoint(skel->progs.trace_enter_setfsgid, "syscalls", "sys_enter_setfsgid");
    skel->links.trace_exit_setfsgid = bpf_program__attach_tracepoint(skel->progs.trace_exit_setfsgid, "syscalls", "sys_exit_setfsgid");

    // capset システムコールに対する設定
    skel->links.trace_enter_capset = bpf_program__attach_tracepoint(skel->progs.trace_enter_capset, "syscalls", "sys_enter_capset");
    skel->links.trace_exit_capset = bpf_program__attach_tracepoint(skel->progs.trace_exit_capset, "syscalls", "sys_exit_capset");

    // prctl システムコールに対する設定
    skel->links.trace_enter_prctl = bpf_program__attach_tracepoint(skel->progs.trace_enter_prctl, "syscalls", "sys_enter_prctl");
    skel->links.trace_exit_prctl = bpf_program__attach_tracepoint(skel->progs.trace_exit_prctl, "syscalls", "sys_exit_prctl");

    // ioctl
    skel->links.trace_enter_ioctl = bpf_program__attach_tracepoint(skel->progs.trace_enter_ioctl, "syscalls", "sys_enter_ioctl");
    skel->links.trace_exit_ioctl = bpf_program__attach_tracepoint(skel->progs.trace_exit_ioctl, "syscalls", "sys_exit_ioctl");

    skel->links.trace_enter_open = bpf_program__attach_tracepoint(
        skel->progs.trace_enter_open,
		"syscalls",                   // カテゴリ名
        "sys_enter_open"              // tracepoint名
        );
    skel->links.trace_exit_openat = bpf_program__attach_tracepoint(
        skel->progs.trace_exit_openat,
        "syscalls",                   // カテゴリ名
        "sys_exit_openat"               // tracepoint名
        );

    skel->links.trace_enter_openat = bpf_program__attach_tracepoint(
        skel->progs.trace_enter_openat,
		"syscalls",                   // カテゴリ名
        "sys_enter_openat"              // tracepoint名
        );
    skel->links.trace_exit_openat = bpf_program__attach_tracepoint(
        skel->progs.trace_exit_openat,
        "syscalls",                   // カテゴリ名
        "sys_exit_openat"               // tracepoint名
        );


    skel->links.trace_enter_openat2 = bpf_program__attach_tracepoint(
        skel->progs.trace_enter_openat2,
		"syscalls",                   // カテゴリ名
        "sys_enter_openat2"              // tracepoint名
        );
    skel->links.trace_exit_openat2 = bpf_program__attach_tracepoint(
        skel->progs.trace_exit_openat2,
        "syscalls",                   // カテゴリ名
        "sys_exit_openat2"               // tracepoint名
        );
    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "pamspy: Failed to create ring buffer\n");
        goto cleanup;
    }

    
    {
        //fprintf(stderr, header);
        fprintf(stderr, "%-6s |%-15s |%-20s |\n", "PID", "UID", "EUID");
        fprintf(stderr, "--------------------------------------------------------------\n");
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "pamspy: Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    pamspy_bpf__destroy( skel);
    return -err;
}

// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include "pamspy_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/******************************************************************************/
/*!
 *  \brief  dump from source code of libpam
 *          This is a partial header
 */
typedef struct pam_handle
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
} pam_handle_t;

/******************************************************************************/
/*!
 *  \brief  ring buffer use to communicate with userland process
 */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");



// イベント構造体
struct event_t {
    u32 pid;
    u32 uid;
    u32 euid;
    u32 suid;
    u32 new_uid;
    u32 new_euid;
    u32 new_suid;
    u32 error_flag;
    u64 syscall_no;
   
    char comm[16];
};

// BPFマップ：システムコール開始時のUID/EUID/SUIDを保存
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);  // PID
    __type(value, struct event_t);  // UID/EUID/SUID
    __uint(max_entries, 1024);
} uid_map SEC(".maps");

int is_privilege_escalation(u32 pid, struct task_struct *task)
{
    struct event_t *existing_event;
    existing_event = bpf_map_lookup_elem(&uid_map, &pid);
    if (existing_event) {
        // データが既に存在する場合は現在の UID/EUID と比較
        u32 current_uid = BPF_CORE_READ(task, real_cred, uid.val);
        u32 current_euid = BPF_CORE_READ(task, real_cred, euid.val);

        if (existing_event->uid != current_uid || existing_event->euid != current_euid) {
            // UID または EUID が変更されている場合、error_flag を 1 に設定
            return 1;
        } else {
            // 変更がない場合は error_flag を 0 に設定
            return 0;
        }
    }
    return 0;
}

// システムコールの実行前にUID/EUID/SUIDを保存、比較
static inline int handle_syscall_enter(struct pt_regs *ctx, u64 syscall_id)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t event = {};

    event.error_flag = is_privilege_escalation(pid,task);
    //event.error_flag = 0;

    // 新しいデータを保存 (存在する場合も更新)
    event.uid = BPF_CORE_READ(task, real_cred, uid.val);
    event.euid = BPF_CORE_READ(task, real_cred, euid.val);
    event.suid = BPF_CORE_READ(task, real_cred, suid.val);
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // UID/EUID/SUIDを保存または更新
    bpf_map_update_elem(&uid_map, &pid, &event, BPF_ANY);

    return 0;
}


static inline int handle_syscall_exit(struct pt_regs *ctx, u64 syscall_id)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 id = syscall_id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t *old_event;
    struct event_t new_event = {};
    // 実行前のUID/EUID/SUIDを取得
    old_event = bpf_map_lookup_elem(&uid_map, &pid);
    if (!old_event) {
        // 実行前のデータがなければスルー
        return 0;
    }
    new_event.error_flag = is_privilege_escalation(pid,task) | old_event->error_flag;

    // 実行後のUID/EUID/SUIDを取得
    new_event.new_uid = BPF_CORE_READ(task, real_cred, uid.val);
    new_event.new_euid = BPF_CORE_READ(task, real_cred, euid.val);
    new_event.new_suid = BPF_CORE_READ(task, real_cred, suid.val);
    new_event.pid = pid;
    bpf_get_current_comm(&new_event.comm, sizeof(new_event.comm));
    
    struct event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        // if(new_event.error_flag){
          e->pid = pid;
          e->uid = old_event->uid;
          e->euid = old_event->euid;
          e->suid = old_event->suid;
          e->new_uid = new_event.new_uid;
          e->new_euid = new_event.new_euid;
          e->new_suid = new_event.new_suid;
          e->error_flag = new_event.error_flag;
          e->syscall_no = id;
          bpf_ringbuf_submit(e, 0);
        // }
        // else {
        //   bpf_ringbuf_discard(e, 0);
        // }
    }

    // 保存したデータを削除
    bpf_map_delete_elem(&uid_map, &pid);
    return 0;
};


// SEC("raw_tracepoint/raw_syscalls/sys_enter")
// int trace_enter_allsyscalls(struct bpf_raw_tracepoint_args *ctx)
// {
//   return handle_syscall_enter(ctx);
// }

// SEC("raw_tracepoint/raw_syscalls/sys_exit")
// int trace_exit_allsyscalls(struct bpf_raw_tracepoint_args *ctx)
// {
//   return handle_syscall_exit(ctx);
// }
// ioctl システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_ioctl")
int trace_enter_ioctl(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx, 16);  // ioctl システムコールの処理
}
SEC("tracepoint/syscalls/sys_exit_ioctl")
int trace_exit_ioctl(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx, 16);  // ioctl システムコールの処理
}

// open システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,11);  // 共通処理を呼び出す
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,11);  // 共通処理を呼び出す
}

// openat システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,11);  // 共通処理を呼び出す
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,11);  // 共通処理を呼び出す
}

// openat2 システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,11);  // 共通処理を呼び出す
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_exit_openat2(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,11);  // 共通処理を呼び出す
}


// execve システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,110);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,110);  // 共通処理を呼び出す
}


// setuid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_enter_setuid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,1);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_exit_setuid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,1);  // 共通処理を呼び出す
}


// setgid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_enter_setgid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,2);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setgid")
int trace_exit_setgid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,2);  // 共通処理を呼び出す
}

// setreuid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_enter_setreuid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,3);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setreuid")
int trace_exit_setreuid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,3);  // 共通処理を呼び出す
}

// setregid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_enter_setregid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,4);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setregid")
int trace_exit_setregid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,4);  // 共通処理を呼び出す
}

// setresuid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_enter_setresuid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,5);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setresuid")
int trace_exit_setresuid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,5);  // 共通処理を呼び出す
}

// setresgid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_enter_setresgid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,6);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setresgid")
int trace_exit_setresgid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,6);  // 共通処理を呼び出す
}

// setfsuid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setfsuid")
int trace_enter_setfsuid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,7);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setfsuid")
int trace_exit_setfsuid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,7);  // 共通処理を呼び出す
}

// setfsgid システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_setfsgid")
int trace_enter_setfsgid(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,8);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_setfsgid")
int trace_exit_setfsgid(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,8);  // 共通処理を呼び出す
}

// capset システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_enter_capset(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,9);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_capset")
int trace_exit_capset(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,9);  // 共通処理を呼び出す
}

// prctl システムコールに対する処理
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_enter_prctl(struct pt_regs *ctx)
{
    return handle_syscall_enter(ctx,10);  // 共通処理を呼び出す
}
SEC("tracepoint/syscalls/sys_exit_prctl")
int trace_exit_prctl(struct pt_regs *ctx)
{
    return handle_syscall_exit(ctx,10);  // 共通処理を呼び出す
}


// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include "pamspy_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";



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
static inline int handle_syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event_t event = {};

    // event.error_flag = is_privilege_escalation(pid,task);
    event.error_flag = 0;

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


static inline int handle_syscall_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 id = ctx->args[1];
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
        if(new_event.error_flag){
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
        }
        else {
          bpf_ringbuf_discard(e, 0);
        }
    }

    // 保存したデータを削除
    bpf_map_delete_elem(&uid_map, &pid);
    return 0;
};


SEC("raw_tracepoint/raw_syscalls/sys_enter")
int trace_enter_allsyscalls(struct bpf_raw_tracepoint_args *ctx)
{
  return handle_syscall_enter(ctx);
}

SEC("raw_tracepoint/raw_syscalls/sys_exit")
int trace_exit_allsyscalls(struct bpf_raw_tracepoint_args *ctx)
{
  return handle_syscall_exit(ctx);
}

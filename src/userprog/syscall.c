#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include "kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

static struct lock files_sync_lock;     /*lock for sychronization between files */
int get_int(int *esp);                  /*get int from the stack*/
unsigned get_unsigned(void *esp);      /*get unsigned from the stack*/
char *get_char_ptr(char *esp);         /*get character pointer*/
void *get_void_ptr(void *esp);         /*get void pointer*/
void validate_void_ptr(const void *pt); /*chack if the pointer is valid*/
 
void syscall_init(void)
{
  // printf ("(syscall_init) : Initializing START\n");
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_sync_lock);
  // printf ("(syscall_init) : Initializing DONE\n");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //Pull and validate then call process_execute
  //B Pull mn l stack 3alashan a switch 
  //Inside kol wrapper bageeb mn l stack w b validate (wrapper : related to userprog logic)
  //Inside wrapper we make actual system call (related to kernel) momken a do some synch 
  // printf ("system call!\n");
  // validate_void_ptr(f->esp);
  int sys_code = *(int *)f->esp;
  // printf ("(syscall_handler) : esp initially at %x\n",f->esp);
  // printf ("00000000  00 01 02 03 04 05 06 07-08 09 0A 0B 0C 0D 0E 0F\n");
  // hex_dump((uintptr_t)(f->esp), f->esp, sizeof(char) * 100, true); 
  (*(int *)f->esp) += 1;
  // printf ("(syscall_handler) : %d\n",sys_code);
  switch (sys_code)
    {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT:
    {
      exit_wrapper(f);
      break;
    }
    case SYS_EXEC:
    {
      exec(sys_code);
      break;
    }
    case SYS_WAIT:
    {
      wait_wrapper(f);
      break;
    }
    case SYS_CREATE:
    {
      break;
    }
    case SYS_REMOVE:
    {
      break;
    }
    case SYS_OPEN:
    {
      open_wrapper(f);
      break;
    }
    case SYS_FILESIZE:
    {
      break;
    }
    case SYS_READ:
    {
      break;
    }
    case SYS_WRITE:
    {
      write_wrapper(f);
      break;
    }
    case SYS_SEEK:
    {
      break;
    }
    case SYS_TELL:
    {
      break;
    }
    case SYS_CLOSE:
    {
      break;
    }
    default:
    {
      exit(-1);
    }
  }
}

void validate_void_ptr(const void *pt)
{
  struct thread *current_thread = thread_current();
  // printf ("(validate_void_ptr) : %x \n",pt );
  // printf ("(validate_void_ptr) : %x \n",current_thread->pagedir);
  // printf ("(validate_void_ptr) : %d \n",!is_user_vaddr((const void *)pt));
  if (pt == NULL || pagedir_get_page(current_thread->pagedir, pt) == NULL || !is_user_vaddr((const void *)pt))
  {
    // printf ("(validate_void_ptr) : NOT VALID EXITTING .....\n");
    exit(-1);
  }
}

void open_wrapper(struct intr_frame *f UNUSED)
{
  void* buffer = get_void_ptr(f->esp);
  // printf ("(open_wrapper) : Openning \n");
  lock_acquire (&files_sync_lock);
  filesys_open (buffer);  
  lock_release (&files_sync_lock);
}
 
void write_wrapper(struct intr_frame *f UNUSED)
{
  // printf ("(write_wrapper) : beging write wrapper\n");

  int fd = get_int(f->esp);
  void* buffer = get_void_ptr(f->esp);
  unsigned size = get_unsigned(f->esp);
  // printf ("(write_wrapper) : file descriptor (ID) %d \n",fd);

  // printf ("00000000  00 01 02 03 04 05 06 07-08 09 0A 0B 0C 0D 0E 0F\n");
  // hex_dump((uintptr_t)(f->esp), f->esp, sizeof(char) * 100, true); 
  f->eax = write(fd, buffer, size);
}
 
void wait_wrapper(struct intr_frame *f UNUSED)
{
  int tid = get_int(f->esp);
  // printf ("(wait_wrapper) : waiting \n");
  f->eax=wait (tid);  
  
}

void exit_wrapper(struct intr_frame *f UNUSED)
{
  int status = get_int(f->esp);
  exit(status);
}

int write(int fd, const void *buffer, unsigned size)
{
  // printf ("(write) : writing #1 !\n");
  if (fd == 0)
  {
    //negative area
    // printf ("(write) : writing #2 !\n");
    return 0;
  }
  else if (fd == 1)
  {
    // printf ("(write) : writing #3 !\n");
    //(It isreasonable to break up larger buffers.) Otherwise, lines of text output by different processes
    //may end up interleaved on the console
    unsigned temp_size = size;
    while (temp_size > 100)
    {
      // printf ("(write) : writing #4 !\n");
      putbuf(buffer, 100);
      temp_size = temp_size - 100;
      buffer = buffer + 100;
    }
    // printf ("(write) : writing #5 !\n");
    putbuf(buffer, temp_size);
    // printf ("(write) : writing #6 !\n");
    return size;
  }
  else
  {
    struct list_elem *e;
    struct list *open_list = &thread_current()->open_file;
    struct file *target_file;
    for (e = list_begin(open_list); e != list_end(open_list); e = list_next(e))
    {
      struct open_file *file = list_entry(e, struct open_file, fileelem);
      if (file->fd == fd)
      {
        target_file = file->ptr;
        break;
      }
    }
    if(target_file == NULL) 
    {
      return -1;
    }
    lock_acquire(&files_sync_lock);
    int returned = file_write(target_file, buffer, size);
    lock_release(&files_sync_lock);
    return returned;
  }
}
 
void exit(int status)
{
  // printf ("exit: exit(%d)\n",status);
  // status : 0 success , non-zero error

  // printf ("(exit) : begin exiting with status %d\n",status);
  struct thread *current_thread = thread_current ();
  printf("%s: exit(%d)\n", current_thread->name, status);
  // struct thread *child = NULL;
  // struct list_elem *elem = list_begin (&current_thread->children);
  // while (elem != list_tail (&current_thread->children)){
  //   printf ("(exit) : ANA FL LOOP YA TE3EM \n");
  //   child = list_entry(elem, struct thread, childelem);
  //   sema_up(&child->parent_child_sync);
  //   elem = list_next (elem);
  // }

  struct thread *parent = thread_current()->parent_thread;
  // printf ("(exit) parent %d waiting on %d\n",parent->tid,parent->waiting_on);
  if(parent != NULL && parent->waiting_on == thread_current()->tid){
    parent->child_exit_status = status;
    parent->waiting_on = -1;
    // sema_up(&parent->parent_child_sync);
    // printf ("(exit) : ANA FL IF YA TE3EM \n");
  }
  else 
  {
    // printf ("(exit) : ANA BRA FL ELSE YA TE3EM \n");
    list_remove(&current_thread->childelem);
  }
  thread_exit ();
  //struct list *open_list = &thread_current()->open_file;
  // for (e = list_begin(open_list); e != list_end(open_list); e = list_next(e))
  // {
  //   struct open_file *file = list_entry(e, struct open_file, fileelem);
  //   file_close(file->ptr);
  // }


  /*struct thread *current_thread = thread_current ();
  int size = list_size (&thread_current()->children);  
  int cnt = 0;
  struct list_elem *e = list_head(&thread_current()->children);

  while (cnt < size)
  {
    e = list_next(e);
    cnt ++;
    //printf ("(exit) : ANA FL LOOP YA TE3EM\n");
    struct thread *child = list_entry(e, struct thread, childelem);
    printf ("(exit) : ANA FL LOOP YA TE3EM child PID : %d\n",size);
    sema_up(&child->parent_child_sync);
  }*/
  // printf ("(exit) : loop is done\n");
 
  // struct list *open_list = &thread_current()->open_file;
  // for (e = list_begin(open_list); e != list_end(open_list); e = list_next(e))
  // {
  //   struct open_file *file = list_entry(e, struct open_file, fileelem);
  //   file_close(file->ptr);
  // }
}
 
int wait(tid_t child_tid UNUSED){
  return process_wait(child_tid);
}
int exec(const char *cmd_line)
{
}
 

 
int get_int(int *esp)
{
  validate_void_ptr((void*)esp + 1);
  return *((int*)esp + 1);
}

unsigned get_unsigned(void *esp)
{
  validate_void_ptr((void*)esp + 3);
  return *((unsigned*)esp + 3);
}

char *get_char_ptr(char *esp)
{
  validate_void_ptr((void *)esp + 1);
  return (char*)(*(int *)esp + 1);
}
 
void *get_void_ptr(void *esp)
{
  validate_void_ptr((void*)esp + 2);
  return (void*)(*((int*)esp + 2));
}
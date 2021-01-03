#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
//Get int
//Get char
//validate void

void
syscall_init (void) 
{
  printf ("(syscall_inint) : Initializing system call\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void validate_void_ptr(const void *pt)
{
  struct thread *current_thread = thread_current();
  // if (pt == NULL || pagedir_get_page(current_thread->pagedir, (const void *)pt) == NULL || !is_user_vaddr((const void *)pt))
  // {
  //   exit(-1);
  // }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //Pull and validate then call process_execute
  //B Pull mn l stack 3alashan a switch 
  //Inside kol wrapper bageeb mn l stack w b validate (wrapper : related to userprog logic)
  //Inside wrapper we make actual system call (related to kernel) momken a do some synch 
  printf ("system call!\n");
  // validate_void_ptr(f->esp);
  int sys_code = *(int *)f->esp;
  switch (sys_code)
  {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT:
    {
      // exit();
      break;
    }
    case SYS_EXEC:
    {
      exec(sys_code);
      break;
    }
    case SYS_WAIT:
    {
      wait_wrapper();
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
  }
  thread_exit ();
}

void exit(int status)
{

  thread_exit();
}

int exec(const char *cmd_line)
{
}

void wait_wrapper()
{
}

int write(int fd, const void *buffer, unsigned size)
{
}

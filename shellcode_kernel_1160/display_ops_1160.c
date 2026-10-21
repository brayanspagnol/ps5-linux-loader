#include "display_ops_1160.h"
#include "shellcode_kernel_args.h"
#include "utils.h"
#include <stddef.h>

/*
 * The 13.60 wake blob runs a table of kernel display calls after the
 * VBIOS/DP/MP3 handoff and before the final SMP rendezvous. These are the
 * matching 11.60 functions, in the same order and with the same 0x18-byte
 * records. Every call takes arg1_edi, mode 2 calls also take arg2_rsi.
 */
_Static_assert(sizeof(ps5_display_op_1160) == 0x18,
               "display-op record layout changed");

const ps5_display_op_1160 ps5_display_ops_1160[29] = {
    {0x00362730, 0, 0, 0},
    {0x00362980, 0, 0, 0},
    {0x00362AD0, 0, 0, 0},
    {0x00362C90, 0, 0, 0},
    {0x00C16F70, 0, 0, 0},
    {0x00333410, 0, 0, 0},
    {0x00751F20, 0, 0, 0},
    {0x00B01800, 0, 0, 0},
    {0x005381C0, 0, 0, 0},
    {0x005383B0, 0, 0, 0},
    {0x00362AA0, 0, 0, 0},
    {0x00B88B80, 0, 0, 0},
    {0x00B896F0, 0, 0, 0},
    {0x00B89900, 0, 0, 0},
    {0x00B89A40, 0, 0, 0},
    {0x00334460, 0, 0, 0},
    {0x00334460, 1, 0, 0},
    {0x00334460, 2, 0, 0},
    {0x00334460, 3, 0, 0},
    {0x00362CC0, 0, 0, 0},
    {0x00538580, 0, 0, 0},
    {0x00538700, 0, 0, 0},
    {0x00B88C70, 0, 0, 0},
    {0x007585F0, 0, 0, 0},
    {0x009DC910, 1, 2, 0x7F0},
    {0x0053D9F0, 0, 0, 0},
    {0x00539460, 1, 0, 0},
    {0x00538ED0, 0, 0, 0},
    {0x00538D70, 0, 0, 0},
};

typedef uint64_t (*display_op1_fn)(uint32_t);
typedef uint64_t (*display_op2_fn)(uint32_t, uint64_t);

// Kept out of line so each kernel call is a tail jump, as in the 13.60 blob.
__attribute__((noinline)) static uint64_t
dispatch_ps5_display_op_1160(uint32_t index) {
  if (index >= 29)
    return 0;

  const ps5_display_op_1160 *op = &ps5_display_ops_1160[index];
  const uintptr_t target = args.ktext + op->ktext_offset;

  if (op->mode == 2)
    return ((display_op2_fn)target)(op->arg1_edi, op->arg2_rsi);
  return ((display_op1_fn)target)(op->arg1_edi);
}

void run_ps5_display_ops_1160(void) {
  for (uint32_t index = 0; index < 29; index++) {
    printf("11.60 display op %u starting\n", index + 1);
    dispatch_ps5_display_op_1160(index);
    printf("11.60 display op %u returned\n", index + 1);
  }
}

/*******************************************************************************
 * sataniccanary.c 
 *
 * Satanic Canary: A GCC plugin implementing various stack canaries.
 *
 * The Satanic Canary gcc plugin implements three types of stack canaries.
 * Two of these are currently enabled, and they are described below.
 *
 * This plugin is merely for testing/exploring stack canaries and what they can
 * do for binary runtime security.  I feel safe in saying that the Basic and
 * TSC Data canaries can be used, but are not perfect.  Canaries are not always
 * impervious to compromise.  Likewise, they can impart overhead to the program
 * being executed.
 *
 * A canary, or stack cookie, is merely a value on the stack which is placed
 * there at compile time in the function prologue.  During runtime, at function
 * epilogue,  the sanity of that value is checked.  If the value has been
 * modified then the canary calls an abort() since the stack has been corrupted
 * (either through bad programming or a malicious intent).
 *
 * The canaries are chosen at 'random' for each function being compiled.
 *
 * The array of structs below in the 'canaries' array are the canaries that can
 * be enabled/disabled:
 *
 * -- Basic Canary: This canary places a random constant value/canary on the
 * stack and this same value should lie there unmodified upon function
 * return/epilogue.  This value will be different for each function compiled.
 *
 * -- TSC Canary: This canary places a value on the stack.  This value is
 * obtained from the more active (low 32bits) of the Timestamp Counter (TSC).
 * The TSC is dynamic and different for each execution of the function at
 * runtime.  This is a really craptastic canary and should not be used.  It is
 * easily compromised if the stack if overrun with the same data.  For each call
 * to a function with this canary enabled, the TSC value is placed twice on the
 * stack, back to back.  If, upon prologue, the two values differ, then the
 * stack is said to be corrupt and the program abort()s out.  Now, if the stack
 * is overwritten with the same value/pattern, then, these two values will still
 * be the same, e.g. and the canary will not detect a corruption... bad, bad
 * canary!
 *
 * -- TSC Data Canary: This canary places a TSC stamp, the low 32-bits, on the
 * stack and XOR's it against read-only data in the CS segment.  That XOR value,
 * (DATA xor TSC) is placed on the stack also.  Upon function epilogue, we
 * verify the stack sanity by XOR'ing the CS data and the (TSC xor DATA) that
 * was pushed onto the stack.  The result should be the TSC value we pushed on
 * the stack as the first value.
 * 
 * Copyright (C) 2012 Matt Davis (enferex) <mattdavis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/gpl-2.0.html>
 ******************************************************************************/

#include <stdio.h>
#include <coretypes.h>
#include <gcc-plugin.h>
#include <gimple.h>
#include <tree.h>
#include <tree-pass.h>
#include <rtl.h>
#include <emit-rtl.h>


/* Printing and debugging aids */
#define P(...) {printf("[+] " __VA_ARGS__); printf("\n");}
#ifdef DEBUG
#define D(...) P(__VA_ARGS__)
#else
#define D(...) /* Nothing */
#endif


/* Bendover */
int plugin_is_GPL_compatible = 0;


/* For the plugin.  This will try to canary-fy each function (to make the
 * functions have a canary).
 */
static bool sataniccanary_gate(void)
{
    return true;
}


/* Forward decls for our canary methods.  Each canary method has a before and
 * after call.  The 'setup' is passed the function-to-be-modified's
 * PROLOGUE_END insn NOTE.  And the 'finish' is passed the
 * function-to-be-modified's EPILOGUE_BEG insn NOTE.  Ideally in 'setup' the
 * canary is placed in the stack.  And the 'finish' is used to verify that the
 * canary has not been modified (e.g. has not keeled over and died from toxic
 * fumes.
 */
static void setup_basic_canary(rtx insn);
static void finish_basic_canary(rtx insn);
static void setup_tsc_canary(rtx insn);
static void finish_tsc_canary(rtx insn);
static void setup_tscdata_canary(rtx insn);
static void finish_tscdata_canary(rtx insn);
typedef void(*canary)(rtx);
struct {canary setup; canary finish;} canaries[] = 
{
    {setup_basic_canary, finish_basic_canary},
    /* {setup_tsc_canary, finish_tsc_canary}, <--- DO NOT ENABLE THIS SUCKS */
    {setup_tscdata_canary, finish_tscdata_canary},
};


/* Insert a static (compile-time known) canary value, it will change once per
 * each time this function is called.  The value comes from rand() but might
 * want to consider using /dev/urandom
 */
static int rng_guard_value;
static void setup_basic_canary(rtx insn)
{
    rtx dec, mov, psh, mem;

    /* Each pair (setup and check) will use this value, it will change each time
     * a new "basic canary" is inserted
     */
    rng_guard_value = rand();
    
    /* mov $<rand>, %rax */
    mov = gen_rtx_SET(DImode, 
        gen_rtx_REG(DImode, 0),
        gen_rtx_CONST_INT(VOIDmode, rng_guard_value));
    
    /* push %rax */
    dec = gen_rtx_PRE_DEC(DImode, stack_pointer_rtx);
    mem = gen_rtx_MEM(DImode, dec);
    psh = gen_rtx_SET(DImode, mem, gen_rtx_REG(DImode, 0));
            
    emit_insn_before(mov, insn);
    emit_insn_before(psh, insn);
}


/* Check that the static canary value has not been stepped on */
static void finish_basic_canary(rtx insn)
{
    /* Get the canary from stack and put it into %rax */
    rtx last, mem, rbx, tmp, label;

    /* pop %rbx */
    rbx = gen_rtx_POST_INC(DImode, stack_pointer_rtx);
    mem = gen_rtx_MEM(DImode, rbx);
    tmp = gen_rtx_SET(DImode, gen_rtx_REG(DImode, 1), mem);
    last = emit_insn_after(tmp, insn);

    /* cmp $666, %rbx */
    tmp = gen_rtx_COMPARE(CCmode,
        gen_rtx_REG(DImode, 1),
        gen_rtx_CONST_INT(VOIDmode, rng_guard_value));
    tmp = gen_rtx_SET(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), tmp);
    last = emit_insn_after(tmp, last);

    /* jeq */
    label = gen_label_rtx(); /* Where we jump to */
    tmp = gen_rtx_EQ(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), const0_rtx);
    tmp = gen_rtx_IF_THEN_ELSE(VOIDmode,
        tmp,                                 /* cmp               */
        gen_rtx_LABEL_REF(VOIDmode, label),  /* Ifeq              */
        pc_rtx);                             /* Else (do nothing) */
    last = emit_jump_insn_after(gen_rtx_SET(VOIDmode, pc_rtx, tmp), last);
    JUMP_LABEL(last) = label;

    /* Call abort() */
    tmp = gen_rtx_SYMBOL_REF(Pmode, "abort");
    tmp = gen_rtx_CALL(Pmode, gen_rtx_MEM(QImode, tmp), const0_rtx);
    last = emit_insn_after(tmp, last);
    emit_label_after(label, last);
}


/* Set the TSC value to the canary value.  Push this value onto the stack twice.
 * The check will pop both values and compare.
 */
static void setup_tsc_canary(rtx insn)
{
    rtx tsc, psh;
    rtvec av, cv, lv;

    av = rtvec_alloc(0);
    cv = rtvec_alloc(0);
    lv = rtvec_alloc(0);

    /* rdtsc */
    tsc = gen_rtx_ASM_OPERANDS(VOIDmode, "rdtsc", "", 0, av, cv, lv, 
                               expand_location(RTL_LOCATION(insn)).line);
    emit_insn_before(tsc, insn);

    /* Push the low end (rax) result of rdtsc.  we figure it has more random
     * values than the higher bits of the rdtsc result.  It is a cycle counter,
     * so the lower bits are more 'fresh' than the higher bits.  We push it
     * twice so that we can compare the two canary values later.
     */
    psh = gen_rtx_PRE_DEC(DImode, stack_pointer_rtx);
    psh = gen_rtx_MEM(DImode, psh);
    psh = gen_rtx_SET(DImode, psh, gen_rtx_REG(DImode, 0));
    emit_insn_before(psh, insn);
    emit_insn_before(psh, insn);
}


/* Pop the two tsc values from the stack, and compare.  The same tsc value was
 * push'd twice, therefore the two values should match.
 */
static void finish_tsc_canary(rtx insn)
{
    rtx pop, mem, cmp, jmp, label, last, call;

    /* pop %rbx, pop %rcx (rax has the return value) */
    mem = gen_rtx_POST_INC(DImode, stack_pointer_rtx);
    mem = gen_rtx_MEM(DImode, mem);
    pop = gen_rtx_SET(DImode, gen_rtx_REG(DImode, 1), mem);
    last = emit_insn_after(pop, insn);
    pop = gen_rtx_SET(DImode, gen_rtx_REG(DImode, 2), mem);
    last = emit_insn_after(pop, last);

    /* cmp %rbx, %rcx */
    cmp = gen_rtx_COMPARE(CCmode,
        gen_rtx_REG(DImode, 1),
        gen_rtx_REG(DImode, 2));
    cmp = gen_rtx_SET(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), cmp);
    last = emit_insn_after(cmp, last);

    /* jeq */
    label = gen_label_rtx();
    jmp = gen_rtx_EQ(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), const0_rtx);
    jmp = gen_rtx_IF_THEN_ELSE(VOIDmode,
        jmp,
        gen_rtx_LABEL_REF(VOIDmode, label),
        pc_rtx);
    jmp = gen_rtx_SET(VOIDmode, pc_rtx, jmp);
    last = emit_jump_insn_after(jmp, last);
    JUMP_LABEL(last) = label;

    /* Call abort() */
    call = gen_rtx_SYMBOL_REF(Pmode, "abort");
    call = gen_rtx_CALL(Pmode, gen_rtx_MEM(QImode, call), const0_rtx);
    last = emit_insn_after(call, last);
    emit_label_after(label, last);
}


/* Push TSC and (TSC xor DATA) value onto the stack.  We verify data by XOR'ing
 * DATA and the (TSC xor DATA) that was pushed onto the stack.
 */
static void setup_tscdata_canary(rtx insn)
{
    rtx tsc, psh, and, xor, eax, ebx, ecx, tmp;
    rtvec av, cv, lv;

    av = rtvec_alloc(0);
    cv = rtvec_alloc(0);
    lv = rtvec_alloc(0);

    /* Registers (for convenience) */
    eax = gen_rtx_REG(DImode, AX_REG);
    ebx = gen_rtx_REG(DImode, BX_REG);
    ecx = gen_rtx_REG(DImode, CX_REG);

    /* rdtsc */
    tsc = gen_rtx_ASM_OPERANDS(VOIDmode, "rdtsc", "", 0, av, cv, lv, 
                               expand_location(RTL_LOCATION(insn)).line);
    emit_insn_before(tsc, insn);

    /* push low 32bits of rdtsc */
    psh = gen_rtx_PRE_DEC(DImode, stack_pointer_rtx);
    psh = gen_rtx_MEM(DImode, psh);
    psh = gen_rtx_SET(DImode, psh, eax);
    emit_insn_before(psh, insn);

    /* Treat the low 32bits of rdtsc as a random value.  We will mask out all
     * but 8 bits of it.  The low 8 bits we then use, like a random value, as an
     * index into the code segment.  We take codesegment + (low-32bits &
     * 0x000F).  This value will be our "DATA" value we xor against the TSC and
     * slap onto the stack.  A TSC+DATA canary.
     *
     * To simulate a "random" data address to use, we use the low 8 bits of the
     * TSC in EAX.  But we still need full eax 32bits, so copy eax into ebx.
     */
    tmp = gen_rtx_SET(DImode, ebx, eax);
    emit_insn_before(tmp, insn);
    and = gen_anddi3(ebx, ebx, GEN_INT(0x000F));
    emit_insn_before(and, insn);

    /* Now get some data from the readonly data segment
     * mov %CS:$rbx, %rcx
     */
    tmp = gen_rtx_ASM_OPERANDS(VOIDmode, "mov %%cs, %%rcx", "", 0, av, cv, lv,
                               expand_location(RTL_LOCATION(insn)).line);
    emit_insn_before(tmp, insn);
    tmp = gen_rtx_SET(DImode, ecx, gen_rtx_PLUS(DImode, ecx, ebx));
    emit_insn_before(tmp, insn);

    /* xor %rcx, %rax */
    xor = gen_xordi3(ecx, ecx, eax);
    emit_insn_before(xor, insn);

    /* push %rcx */
    psh = gen_rtx_PRE_DEC(DImode, stack_pointer_rtx);
    psh = gen_rtx_MEM(DImode, psh);
    psh = gen_rtx_SET(DImode, psh, ecx);
    emit_insn_before(psh, insn);
}


/* XOR the TSC value on the stack and the (TSC xor DATA) value on the stack.
 * The xor'ing of these two values should equal the spot in data.  If not, the
 * stack has been stepped on.
 */
static void finish_tscdata_canary(rtx insn)
{
    rtx and, psh, pop, mem, eax, ebx, ecx, edx;
    rtx last, xor, cmp, jmp, label, call;
    rtvec av, cv, lv;

    /* Convenience */
    eax = gen_rtx_REG(DImode, AX_REG);
    ebx = gen_rtx_REG(DImode, BX_REG);
    ecx = gen_rtx_REG(DImode, CX_REG);
    edx = gen_rtx_REG(DImode, DX_REG);
    av = rtvec_alloc(0);
    cv = rtvec_alloc(0);
    lv = rtvec_alloc(0);

    /* Now pop the values off the stack (TSC xor DATA) and then TSC */
    mem = gen_rtx_POST_INC(DImode, stack_pointer_rtx);
    mem = gen_rtx_MEM(DImode, mem);
    pop = gen_rtx_SET(DImode, edx, mem);  /* TSC xor DATA */
    last = emit_insn_after(pop, insn);
    pop = gen_rtx_SET(DImode, ebx, mem);  /* TSC */
    last = emit_insn_after(pop, last);

    /* Push eax so we can save the return value (we need the register) */
    psh = gen_rtx_PRE_DEC(DImode, stack_pointer_rtx);
    psh = gen_rtx_MEM(DImode, psh);
    psh = gen_rtx_SET(DImode, psh, eax);
    last = emit_insn_after(psh, last);

    /* Now get the DATA value CS:(tsc-based-offset) and put it in ecx.
     * Remember we use the low-32bits of the TSC (which was stored on the stack
     * at function prologue).  We mask all but the last 8 bits and use the
     * resulting value as an offset to the code segment.  This value is called
     * the DATA which we xor against the TSC.
     */
    mem = gen_rtx_SET(DImode, eax, ebx);           /* mov %ebx, $eax */
    last = emit_insn_after(mem, last);
    and = gen_anddi3(eax, eax, GEN_INT(0x000F));   /* and %eax, $0x000f */
    last = emit_insn_after(and, last);
    mem = gen_rtx_ASM_OPERANDS(VOIDmode, "mov %%cs, %%rcx", "", 0, av, cv, lv,
                               expand_location(RTL_LOCATION(insn)).line);
    last = emit_insn_after(mem, last);
    mem = gen_rtx_SET(DImode, ecx, gen_rtx_PLUS(DImode, ecx, eax));
    last = emit_insn_after(mem, last); /* add %eax, %ecx */

    /* Restore the return value (put 'er back into rax) */
    mem = gen_rtx_POST_INC(DImode, stack_pointer_rtx);
    mem = gen_rtx_MEM(DImode, mem);
    pop = gen_rtx_SET(DImode, eax, mem);  /* Return value */
    last = emit_insn_after(pop, last);

    /* Now xor (TSC xor DATA) and DATA */
    xor = gen_xordi3(ecx, ecx, edx);
    last = emit_insn_after(xor, last);

    /* Now compare the xor'd value (ecx) and the originally push'd low 32bits of
     * the TSC (ebx) (they should match)
     * cmp %rcx, %rbx 
     */
    cmp = gen_rtx_COMPARE(CCmode, ecx, ebx);
    cmp = gen_rtx_SET(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), cmp);
    last = emit_insn_after(cmp, last);

    /* jeq */
    label = gen_label_rtx();
    jmp = gen_rtx_EQ(VOIDmode, gen_rtx_REG(CCmode, FLAGS_REG), const0_rtx);
    jmp = gen_rtx_IF_THEN_ELSE(
        VOIDmode, jmp, gen_rtx_LABEL_REF(VOIDmode, label), pc_rtx);
    jmp = gen_rtx_SET(VOIDmode, pc_rtx, jmp);
    last = emit_jump_insn_after(jmp, last);
    JUMP_LABEL(last) = label;

    /* Call abort() */
    call = gen_rtx_SYMBOL_REF(Pmode, "abort");
    call = gen_rtx_CALL(Pmode, gen_rtx_MEM(QImode, call), const0_rtx);
    last = emit_insn_after(call, last);
    emit_label_after(label, last);
}


static unsigned sataniccanary_exec(void)
{
    int idx;
    rtx insn;

    P("Adding canary to: %s", get_name(cfun->decl));

    /* Choose a canary method to use */
    idx = rand() % sizeof(canaries)/sizeof(canaries[0]);

    /* For each instruction in this function */
    for (insn=get_insns(); insn; insn=NEXT_INSN(insn))
      if (NOTE_P(insn) && (NOTE_KIND(insn) == NOTE_INSN_PROLOGUE_END))
        canaries[idx].setup(insn);
      else if (NOTE_P(insn) && NOTE_KIND(insn) == NOTE_INSN_EPILOGUE_BEG)
        canaries[idx].finish(insn);

#ifdef DEBUG
    print_rtl(stdout, get_insns());
#endif

    return 0;
}


static struct rtl_opt_pass sataniccanary = 
{
    .pass.type = RTL_PASS,
    .pass.name = "sataniccanary",
    .pass.gate = sataniccanary_gate,
    .pass.execute = sataniccanary_exec,
    .pass.todo_flags_finish = TODO_dump_func,
};


/* Return 0 on success or error code on failure */
int plugin_init(
    struct plugin_name_args   *info,  /* Argument info  */
    struct plugin_gcc_version *ver)   /* Version of GCC */
{
    struct register_pass_info pass = 
    {
        .pass = &sataniccanary.pass,
        .reference_pass_name = "pro_and_epilogue",
        .ref_pass_instance_number = 0,
        .pos_op = PASS_POS_INSERT_AFTER,
    };

    /* Some canaries (basic canary) call rand() */
    srand(time(NULL));

    register_callback("sataniccanary", PLUGIN_PASS_MANAGER_SETUP, NULL, &pass);
    return 0;
}

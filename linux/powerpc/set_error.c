static int
arch_set_error(struct tcb *tcp)
{
	ppc_regs.gpr[3] = tcp->u_error;
	ppc_regs.ccr |= 0x10000000;
	return upoke(tcp, sizeof(long) * PT_CCR, ppc_regs.ccr) ||
	       upoke(tcp, sizeof(long) * (PT_R0 + 3), ppc_regs.gpr[3]);
}

static int
arch_set_success(struct tcb *tcp)
{
	ppc_regs.gpr[3] = tcp->u_rval;
	ppc_regs.ccr &= ~0x10000000;
	return upoke(tcp, sizeof(long) * PT_CCR, ppc_regs.ccr) ||
	       upoke(tcp, sizeof(long) * (PT_R0 + 3), ppc_regs.gpr[3]);
}

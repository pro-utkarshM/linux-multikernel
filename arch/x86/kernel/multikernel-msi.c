// SPDX-License-Identifier: GPL-2.0-only
/*
 * multikernel-msi.c - PCI/MSI messages mediated by the spawning kernel
 *
 * With interrupt remapping active on the machine, a device MSI composed
 * here would be blocked by the IOMMU this kernel does not own. The
 * kernel that owns it says so in the instance device tree, and this
 * parent domain then asks it for every message: the owner programs a
 * SID-verified remapping entry targeting the (cpu, vector) the vector
 * domain picked and hands back the remappable message, opaque here.
 * The message is index-stable, so moving an interrupt to another CPU
 * only retargets the owner's entry; nothing at the device changes.
 *
 * Without interrupt remapping there is nothing between the device and
 * the LAPICs, and the native MSI path composes messages as always.
 */
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/multikernel.h>
#include <linux/irqchip/irq-msi-lib.h>

#include <asm/apic.h>
#include <asm/msi.h>
#include <asm/irqdomain.h>
#include <asm/hw_irq.h>

struct mk_msi_data {
	struct mk_msi_irte irte;
	struct msi_msg msg;
	u16 domain;
	u8 bus;
	u8 devfn;
};

static void mk_msi_compose_msg(struct irq_data *irqd, struct msi_msg *msg)
{
	struct mk_msi_data *data = irqd->chip_data;

	*msg = data->msg;
}

static int mk_msi_retarget(struct irq_data *irqd)
{
	struct mk_msi_data *data = irqd->chip_data;
	struct irq_cfg *cfg = irqd_cfg(irqd);

	return mk_msi_irte_modify(data->domain, data->bus, data->devfn,
				  data->irte.iommu_seq, data->irte.index,
				  cfg->dest_apicid, cfg->vector);
}

static int mk_msi_set_affinity(struct irq_data *irqd,
			       const struct cpumask *mask, bool force)
{
	struct irq_data *parent = irqd->parent_data;
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret < 0 || ret == IRQ_SET_MASK_OK_DONE)
		return ret;

	mk_msi_retarget(irqd);
	vector_schedule_cleanup(irqd_cfg(irqd));

	return IRQ_SET_MASK_OK_DONE;
}

static struct irq_chip mk_msi_chip = {
	.name			= "MK-IR",
	.irq_ack		= apic_ack_irq,
	.irq_set_affinity	= mk_msi_set_affinity,
	.irq_compose_msi_msg	= mk_msi_compose_msg,
};

static int mk_msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
			       unsigned int nr_irqs, void *arg)
{
	struct irq_alloc_info *info = arg;
	struct mk_msi_data *data;
	struct irq_data *irqd;
	struct pci_dev *pdev;
	struct irq_cfg *cfg;
	int ret;

	if (!info || nr_irqs > 1)
		return -EINVAL;	/* Multi-vector MSI is not advertised */
	if (info->type != X86_IRQ_ALLOC_TYPE_PCI_MSI &&
	    info->type != X86_IRQ_ALLOC_TYPE_PCI_MSIX)
		return -EINVAL;

	pdev = msi_desc_to_pci_dev(info->desc);
	if (!pdev)
		return -EINVAL;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	data = kzalloc_obj(*data, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out_free_parent;
	}

	data->domain = pci_domain_nr(pdev->bus);
	data->bus = pdev->bus->number;
	data->devfn = pdev->devfn;

	irqd = irq_domain_get_irq_data(domain, virq);
	cfg = irqd_cfg(irqd);
	ret = mk_msi_irte_alloc(data->domain, data->bus, data->devfn,
				cfg->dest_apicid, cfg->vector, &data->irte);
	if (ret) {
		kfree(data);
		goto out_free_parent;
	}

	data->msg.address_lo = data->irte.addr_lo;
	data->msg.address_hi = data->irte.addr_hi;
	data->msg.data = data->irte.data;

	irqd->hwirq = ((irq_hw_number_t)data->irte.iommu_seq << 32) |
		      data->irte.index;
	irqd->chip = &mk_msi_chip;
	irqd->chip_data = data;

	return 0;

out_free_parent:
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
	return ret;
}

static void mk_msi_domain_free(struct irq_domain *domain, unsigned int virq,
			       unsigned int nr_irqs)
{
	unsigned int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *irqd = irq_domain_get_irq_data(domain, virq + i);

		if (irqd && irqd->chip_data) {
			struct mk_msi_data *data = irqd->chip_data;

			mk_msi_irte_free(data->irte.iommu_seq, data->irte.index);
			kfree(data);
			irq_domain_reset_irq_data(irqd);
		}
	}
	irq_domain_free_irqs_common(domain, virq, nr_irqs);
}

/*
 * The real vector is assigned when the interrupt is activated, so the
 * owner's entry is retargeted here; the composed message is unaffected.
 */
static int mk_msi_domain_activate(struct irq_domain *domain,
				  struct irq_data *irqd, bool reserve)
{
	mk_msi_retarget(irqd);
	return 0;
}

static const struct irq_domain_ops mk_msi_domain_ops = {
	.alloc		= mk_msi_domain_alloc,
	.free		= mk_msi_domain_free,
	.activate	= mk_msi_domain_activate,
};

static const struct msi_parent_ops mk_msi_parent_ops = {
	.supported_flags	= X86_VECTOR_MSI_FLAGS_SUPPORTED,
	.bus_select_token	= DOMAIN_BUS_DMAR,
	.bus_select_mask	= MATCH_PCI_MSI,
	.prefix			= "MK-IR-",
	.init_dev_msi_info	= msi_parent_init_dev_msi_info,
};

struct irq_domain * __init mk_create_pci_msi_domain(void)
{
	struct irq_domain_info info = {
		.ops		= &mk_msi_domain_ops,
		.parent		= x86_vector_domain,
		.domain_flags	= IRQ_DOMAIN_FLAG_ISOLATED_MSI,
	};
	struct irq_domain *d;

	if (!mk_msi_mediated)
		return native_create_pci_msi_domain();

	/*
	 * Device domains chain their setup through the vector domain's
	 * parent ops, which only the native path installs.
	 */
	if (!native_create_pci_msi_domain())
		return NULL;

	info.fwnode = irq_domain_alloc_named_fwnode("MK-IR");
	if (!info.fwnode)
		return x86_vector_domain;

	d = msi_create_parent_irq_domain(&info, &mk_msi_parent_ops);
	if (!d) {
		irq_domain_free_fwnode(info.fwnode);
		pr_warn("MK-IR: no mediated MSI domain, falling back to native messages\n");
		return x86_vector_domain;
	}

	pr_info("MK-IR: PCI/MSI messages mediated by the spawning kernel\n");
	return d;
}

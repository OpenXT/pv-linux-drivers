#ifndef _XEN_XEN_H
#define _XEN_XEN_H

enum xen_domain_type {
	XEN_NATIVE,		/* running on bare hardware    */
	XEN_PV_DOMAIN,		/* running in a PV domain      */
	XEN_HVM_DOMAIN,		/* running in a Xen hvm domain */
};

extern enum xen_domain_type xen_dkms_domain_type;

#define xen_domain()		(1)
#define xen_pv_domain()		(0)
#define xen_hvm_domain()	(1)


#endif	/* _XEN_XEN_H */

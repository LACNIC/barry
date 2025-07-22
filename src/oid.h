#ifndef SRC_OID_H_
#define SRC_OID_H_

extern int NID_ip_v2;
extern int NID_asn_v2;
extern int NID_resource_policy_v1;
extern int NID_resource_policy_v2;

void oid_setup(void);

char const *oid2str(char const *);

#endif /* SRC_OID_H_ */

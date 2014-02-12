#ifndef DNS_H
#define    DNS_H
     
#define    DNS_MSG_END    -2
     
#define    dns_mx_query(str)    dns_resolve((str),T_MX)
#define    dns_mx_expand()        dns_findmx(T_MX)
     
#define    foreach_mxrr(p,dn)    while(dns_mx_expand()!=DNS_MSG_END    \
                        &&(!dns_get_mxrr(&p,dn,MAXDNAME)))
     
    void dns_init(void);
    int dns_get_mxrr(unsigned short *,unsigned char *,unsigned int);
    int dns_resolve(char *,int);
    int dns_findmx(int);
     
    #endif /* #ifndef MONNAND_DNS_H */ 

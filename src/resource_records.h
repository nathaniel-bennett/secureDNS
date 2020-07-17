#ifndef DNSWRAPPER__RESOURCE_RECORDS_H
#define DNSWRAPPER__RESOURCE_RECORDS_H


typedef struct dns_rr_st dns_rr;


struct dns_rr_st {
    char *cname;
    time_t ttl;
    uint8_t is_other_type;
    uint8_t is_cname;
    union {
        char *aliased_host;
        struct sockaddr *addr;
        unsigned char *data;
    };
    uint16_t resp_len;

    dns_rr *next;
};



int form_question_record(unsigned char *buf, ssize_t buf_size,
            uint16_t id, const char *hostname, int type);

int parse_dns_records(unsigned char *buf,
            int buf_len, const char *hostname, uint16_t id, dns_rr **out);

int has_expired_records(dns_rr *records);

void dns_records_free(dns_rr *records);

#endif

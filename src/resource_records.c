#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "resource_records.h"
#include "dns_context.h"
#include "../include/dns.h"

#define MAX_HOSTNAME 255

#define DNS_HEADER_SIZE 12
#define DNS_TYPE_SIZE 2
#define DNS_CLASS_SIZE 2
#define DNS_TTL_SIZE 4
#define DNS_RDATA_LEN_SIZE 2

#define HOSTNAME_WIRE_SIZE(hostname) (strlen(hostname) + 2)

/** returns the *maximum* size of the given hostname in wire format */
#define QUERY_WIRE_SIZE(hostname) \
            (HOSTNAME_WIRE_SIZE(hostname) + DNS_TYPE_SIZE + DNS_CLASS_SIZE)

#define DNS_RECURSION_DESIRED_BIT 0x01

#define DNS_IN_CLASS 0x0001
#define DNS_A_TYPE 0x0001
#define DNS_AAAA_TYPE 0x001c
#define DNS_CNAME_TYPE 0x0005

#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_BAD_HOSTNAME 3

#define OTHER_RECORD_FLAG 0x01
#define CNAME_RECORD_FLAG 0x02

#define recursion_supported(header) ((header)[3] & 0x80)
#define is_response_record(header) ((header)[2] & 0x80)
#define is_truncated_record(header) ((header)[2] & 0x02)

#define get_header_rcode(header) ((header)[3] & 0x0f)
#define get_header_opcode(header) ((header)[2] >> 3 & 0x0f)
#define get_question_cnt(header) \
            ((uint16_t) (((header)[4] << 8) + (header)[5]))
#define get_answer_rr_cnt(header) \
            ((uint16_t) (((header)[6] << 8) + (header)[7]))
#define get_authority_rr_cnt(header) \
            ((uint16_t) (((header)[8] << 8) + (header)[9]))
#define get_additional_rr_cnt(header) \
            (uint16_t) (((header)[10] << 8) + (header)[11])
#define get_rr_cnt(wire) (get_answer_rr_cnt(wire) \
            + get_authority_rr_cnt(wire) + get_additional_rr_cnt(wire))


typedef struct dns_wire_st dns_wire;


struct dns_wire_st {
    unsigned char * const data; /* data ptr shouldn't be changed once set */
    const int length; /* neither should length */
    int pos;
};


int parse_dns_record(dns_wire *wire,
            const char *hostname, uint16_t id, dns_rr **out);

int verify_record_info(dns_wire *wire, const char *hostname, uint16_t id);
int parse_query(dns_wire *wire, dns_rr **out);
int parse_rr(dns_wire *wire, dns_rr **out);
dns_rr *concat_records(dns_rr *records, dns_rr *new_records);

unsigned char *get_header(dns_wire *wire);
void clear_header(unsigned char *header);
void set_header_id(unsigned char *header, uint16_t id);
void set_header_recursion_desired(unsigned char *header);
void set_header_question_cnt(unsigned char *header, uint16_t cnt);
uint16_t get_header_id(unsigned char *header);
int check_dns_resp_header(unsigned char *header, uint16_t id);

void set_rr_type(dns_wire *wire, uint16_t type);
void set_rr_class(dns_wire *wire, uint16_t class);
uint16_t get_rr_type(dns_wire *wire);
uint16_t get_rr_class(dns_wire *wire);
uint32_t get_rr_ttl(dns_wire *wire);
uint16_t get_rr_rdata_len(dns_wire *wire);

int get_ipv4_rdata(dns_wire *wire, uint16_t rdata_len, struct sockaddr **addr);
int get_ipv6_rdata(dns_wire *wire, uint16_t rdata_len, struct sockaddr **addr);
int get_rr_rdata(dns_wire *wire, uint16_t rdata_len, unsigned char **out);

int name_ascii_to_wire(dns_wire *wire, const char *name);
int name_ascii_from_wire(dns_wire *wire, char **out);
int buf_name_from_wire(dns_wire *wire, char *buf, int buf_len);
int name_ptr_from_wire(dns_wire *wire);



/*******************************************************************************
 *                  FUNCTIONS FOR RESOURCE RECORD CREATION
 ******************************************************************************/


int form_question_record(unsigned char *buf,
            ssize_t buf_size, uint16_t id, const char *hostname, int type)
{
    dns_wire wire = {
        .data = buf,
        .length = buf_size,
        .pos = 0
    };

    if (strlen(hostname) + 1 > MAX_HOSTNAME)
        return EAI_NONAME;

    unsigned char *header = get_header(&wire);
    if (header == NULL)
        return EAI_FAIL;

    /* header settings */
    clear_header(header);
    set_header_id(header, id);
    set_header_recursion_desired(header);
    set_header_question_cnt(header, 1);

    if (name_ascii_to_wire(&wire, hostname) != 0)
        return EAI_FAIL;

    if (type == AF_INET)
        set_rr_type(&wire, DNS_A_TYPE);
    else /* (type == AF_INET6) */
        set_rr_type(&wire, DNS_AAAA_TYPE);

    set_rr_class(&wire, DNS_IN_CLASS);

    return wire.pos;
}


int parse_dns_records(unsigned char *buf,
            int buf_len, const char *hostname, uint16_t id, dns_rr **out)
{
    dns_wire wire = {
        .data = buf,
        .length = buf_len,
        .pos = 0
    };
    dns_rr *records = NULL, *tmp = NULL;
    int i, ret;

    /* we sent two queries: an A query and an AAAA query */
    for (i = 0; i < DNS_REQUEST_CNT; i++) {
        ret = parse_dns_record(&wire, hostname, id, &tmp);
        if (ret < 0) {
            tmp = NULL;
            goto err;
        }

        records = concat_records(records, tmp);
    }

    if (records == NULL)
        return EAI_NODATA;

    *out = records;
    return 0;
err:
    if (records != NULL)
        dns_records_free(records);
    if (tmp != NULL)
        dns_records_free(tmp);

    return ret;
}


int parse_dns_record(dns_wire *wire,
            const char *hostname, uint16_t id, dns_rr **out)
{
    dns_rr *tmp = NULL, *records = NULL;
    int i, ret, record_cnt;
    char *cname = strdup(hostname);
    if (cname == NULL)
        return EAI_MEMORY;

    ret = verify_record_info(wire, hostname, id);
    if (ret < 0)
        goto err;

    record_cnt = ret;

    for (i = 0; i < record_cnt; i++) {
        ret = parse_rr(wire, &tmp);
        if (ret != 0)
            goto err;

        if (tmp->flags & OTHER_RECORD_FLAG) {
            if (tmp->flags & CNAME_RECORD_FLAG) {
                /* replace current cname with the new cname found in the record */
                free(cname);
                cname = tmp->aliased_host; /* we already converted from wire */
                tmp->aliased_host = NULL;
            }

            dns_records_free(tmp);
            continue;
        }

        if (strcmp(tmp->cname, cname) != 0) {
            ret = EAI_FAIL;
            goto err;
        }

        records = concat_records(records, tmp);
    }

    free(cname);
    *out = records;

    return 0;
err:
    if (records != NULL)
        dns_records_free(records);
    if (tmp != NULL && tmp != records)
        dns_records_free(tmp);

    free(cname);
    return ret;
}


void dns_records_free(dns_rr *records)
{
    if (records == NULL)
        return;

    if (records->cname != NULL)
        free(records->cname);
    if (records->data != NULL)
        free(records->data);
    if (records->next != NULL)
        dns_records_free(records->next);

    free(records);
}


/*******************************************************************************
 *                      ASCII/WIRE FORMAT CONVERSION
 ******************************************************************************/

/*
 * Convert a DNS name from string representation (dot-separated labels)
 * to DNS wire format, using the provided byte array (wire).  Return
 * the number of bytes used by the name in wire format.
 *
 * INPUT:  name: the string containing the domain name
 * INPUT:  wire: a pointer to the array of bytes where the
 *              wire-formatted name should be constructed
 * OUTPUT: the length of the wire-formatted name.
 */
int name_ascii_to_wire(dns_wire *wire, const char *name)
{
    int i = 0;
    uint8_t digit_cnt = 0;
    unsigned char *last = &wire->data[wire->pos];

    if (wire->pos + QUERY_WIRE_SIZE(name) > wire->length)
        return EAI_FAIL;

    /* root name case */
    if (strcmp(name, ".") == 0) {
        wire->data[wire->pos] = '\0';
        wire->pos += 1;
        return 0;
    }

    while (name[i] != '\0') {
        if (name[i] == '.') {
            *last = digit_cnt;
            last = &wire->data[wire->pos + i+1];
            digit_cnt = 0;

        } else {
            wire->data[wire->pos + i+1] = name[i];
            digit_cnt++;
        }

        i++;
    }

    *last = digit_cnt;

    wire->pos += i+2;
    return 0;
}


int name_ascii_from_wire(dns_wire *wire, char **out)
{
    *out = malloc(MAX_HOSTNAME);
    if (*out == NULL)
        return EAI_MEMORY;

    return buf_name_from_wire(wire, *out, MAX_HOSTNAME);
}


/*
 * Extract the wire-formatted DNS name at the offset specified by
 * *pos in the array of bytes provided (wire) and return its string
 * representation (dot-separated labels) in a char array allocated for
 * that purpose.  Update the value pointed to by pos to the next
 * value beyond the name.
 *
 * INPUT:  wire: a pointer to an array of bytes
 * INPUT:  pos, a pointer to the index in the wire where the
 *              wire-formatted name begins
 * OUTPUT: a string containing the string representation of the name,
 *              allocated on the heap.
 */
int buf_name_from_wire(dns_wire *wire, char *buf, int buf_len)
{
    int i = 0, ret;

    if (wire->pos >= wire->length)
        return EAI_FAIL;

    while (wire->data[wire->pos] != '\0') {
        if (wire->data[wire->pos] < 0xc0) {
            uint8_t word_len = wire->data[wire->pos];
            wire->pos++;

            /* catch buffer overflow */
            if ((i + word_len) >= buf_len
                        || (wire->pos + word_len) >= wire->length)
                return EAI_FAIL;

            memcpy(&buf[i], &wire->data[wire->pos], word_len);

            wire->pos += word_len;
            i += word_len + 1;

            buf[i-1] = '.';

        } else {  /* compression case */
            dns_wire ptr_wire = {
                .data = wire->data,
                .length = wire->pos, /* avoids infinite recursion */
            };

            ptr_wire.pos = name_ptr_from_wire(wire);
            if (ptr_wire.pos < 0)
                return EAI_FAIL;

            ret = buf_name_from_wire(&ptr_wire, &buf[i], buf_len - i);
            return (ret < 0) ? ret : (i + ret);
        }
    }

    wire->pos++;

    if (i > 0)
        i-= 1;
    buf[i] = '\0';


    return i;
}


int name_ptr_from_wire(dns_wire *wire)
{
    int ptr;

    if (wire->pos + 2 > wire->length)
        return -1;

    ptr = ((int) wire->data[wire->pos] & ~0xc0) << 8;
    ptr += (int) wire->data[wire->pos + 1];

    wire->pos += 2;

    return ptr;
}

/*******************************************************************************
 *                 HELPER FUNCTIONS FOR PARSING DNS RESPONSES
 ******************************************************************************/


int check_dns_resp_header(unsigned char *header, uint16_t id)
{
    uint16_t resp_id = get_header_id(header);
    if (resp_id != id)
        return -1;

    if (!is_response_record(header))
        return EAI_FAIL;

    if (get_header_opcode(header) != DNS_OPCODE_QUERY)
        return EAI_FAIL;

    if (is_truncated_record(header))
        return EAI_FAIL;

    if (!recursion_supported(header))
        return EAI_FAIL;

    if (get_header_rcode(header) == DNS_RCODE_BAD_HOSTNAME)
        return EAI_NODATA;

    if (get_header_rcode(header) != DNS_RCODE_NO_ERROR)
        return EAI_FAIL;


    if (get_question_cnt(header) != 1)
        return EAI_FAIL;

    return 0;
}


int verify_record_info(dns_wire *wire, const char *hostname, uint16_t id)
{

    int record_cnt, ret;
    dns_rr *tmp;
    unsigned char *header = get_header(wire);
    if (header == NULL)
        return EAI_FAIL;

    ret = check_dns_resp_header(header, id);
    if (ret != 0)
        return ret;

    record_cnt = get_rr_cnt(header);

    ret = parse_query(wire, &tmp);
    if (ret != 0)
        return ret;

    if (strcmp(tmp->cname, hostname) != 0) {
        dns_records_free(tmp);
        return EAI_FAIL;
    }

    dns_records_free(tmp);
    return record_cnt;
}


int parse_query(dns_wire *wire, dns_rr **out)
{
    int ret;

    dns_rr *record = calloc(1, sizeof(dns_rr));
    if (record == NULL)
        return EAI_MEMORY;

    /* extract name from wire */
    ret = name_ascii_from_wire(wire, &record->cname);
    if (ret < 0)
        goto err;

    /* extract type from wire */
    uint16_t type = get_rr_type(wire);
    uint16_t class = get_rr_class(wire);


    if ((type != DNS_A_TYPE && type != DNS_AAAA_TYPE)
                || (class != DNS_IN_CLASS)) {
        ret = EAI_FAIL;
        goto err;
    }

    *out = record;
    return 0;
err:

    dns_records_free(record);
    return ret;
}


/*
 * Extract the wire-formatted resource record at the offset specified by
 * *pos in the array of bytes provided (wire) and return a
 * dns_rr (struct) populated with its contents. Update the value
 * pointed to by pos to the next value beyond the resource record.
 *
 * INPUT:  wire: a pointer to an array of bytes
 * INPUT:  pos: a pointer to the index in the wire where the
 *              wire-formatted resource record begins
 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
 *              we are extracting a full resource record or only a
 *              query (i.e., in the question section of the DNS
 *              message).  In the case of the latter, the ttl,
 *              rdata_len, and rdata are skipped.
 * OUTPUT: the resource record (struct)
 */
int parse_rr(dns_wire *wire, dns_rr **out)
{
    int ret;

    dns_rr *record = calloc(1, sizeof(dns_rr));
    if (record == NULL)
        return EAI_MEMORY;

    /* extract name from wire */
    ret = name_ascii_from_wire(wire, &record->cname);
    if (ret < 0)
        goto err;

    if ((wire->pos + DNS_TYPE_SIZE + DNS_CLASS_SIZE
         + DNS_TTL_SIZE + DNS_RDATA_LEN_SIZE) > wire->length) {
        ret = EAI_FAIL;
        goto err;
    }

    uint16_t type = get_rr_type(wire);
    uint16_t class = get_rr_class(wire);
    record->ttl = time(NULL) + (time_t) get_rr_ttl(wire);
    record->resp_len = get_rr_rdata_len(wire);

    if ((class != DNS_IN_CLASS)
                || (wire->pos + record->resp_len > wire->length)) {
        ret = EAI_FAIL;
        goto err;
    }

    if (type == DNS_CNAME_TYPE) {
        record->flags |= OTHER_RECORD_FLAG | CNAME_RECORD_FLAG;
        ret = name_ascii_from_wire(wire, &record->aliased_host);

    } else if (type == DNS_A_TYPE) {
        ret = get_ipv4_rdata(wire, record->resp_len, &record->addr);

    } else if (type == DNS_AAAA_TYPE) {
        ret = get_ipv6_rdata(wire, record->resp_len, &record->addr);

    } else {
        record->flags |= OTHER_RECORD_FLAG;
        ret = get_rr_rdata(wire, record->resp_len, &record->data);
    }

    if (ret < 0)
        goto err;

    *out = record;
    return 0;
err:
    if (record != NULL)
        dns_records_free(record);
    *out = NULL;
    return ret;
}


dns_rr *concat_records(dns_rr *records, dns_rr *new_records)
{
    dns_rr *last = records;

    if (records == NULL)
        return new_records;

    while (last->next != NULL)
        last = last->next;

    last->next = new_records;

    return records;
}


/*******************************************************************************
 *             FUNCTIONS TO SET RESOURCE RECORD INFO ON THE WIRE
 ******************************************************************************/


unsigned char *get_header(dns_wire *wire)
{
    if (wire->pos + DNS_HEADER_SIZE > wire->length) {
        return NULL;
    } else {
        unsigned char *header = &wire->data[wire->pos];
        wire->pos += DNS_HEADER_SIZE;

        return header;
    }
}


void clear_header(unsigned char *header)
{
    memset(header, 0, DNS_HEADER_SIZE);
}


void set_header_id(unsigned char *header, uint16_t id)
{
    header[0] = id >> 8;
    header[1] = id & 0xff;
}


void set_header_recursion_desired(unsigned char *header)
{
    header[2] |= DNS_RECURSION_DESIRED_BIT;
}


void set_header_question_cnt(unsigned char *header, uint16_t cnt)
{
    header[4] = cnt >> 8;
    header[5] = cnt & 0xff;
}


void set_rr_type(dns_wire *wire, uint16_t type)
{
    wire->data[wire->pos] = type >> 8;
    wire->data[wire->pos+1] = type & 0xff;

    wire->pos += DNS_TYPE_SIZE;
}


void set_rr_class(dns_wire *wire, uint16_t class)
{
    wire->data[wire->pos] = class >> 8;
    wire->data[wire->pos+1] = class & 0xff;

    wire->pos += DNS_CLASS_SIZE;
}

/*******************************************************************************
 *           FUNCTIONS TO RETRIEVE INFO FROM THE RESOURCE RECORD
 ******************************************************************************/


uint16_t get_rr_type(dns_wire *wire)
{
    uint16_t type = ((uint16_t) wire->data[wire->pos]) << 8;
    type += (uint16_t) wire->data[wire->pos+1];

    wire->pos += DNS_TYPE_SIZE;

    return type;
}


uint16_t get_rr_class(dns_wire *wire)
{
    uint16_t class = ((uint16_t) wire->data[wire->pos]) << 8;
    class += (uint16_t) wire->data[wire->pos+1];

    wire->pos += DNS_CLASS_SIZE;

    return class;
}


uint32_t get_rr_ttl(dns_wire *wire)
{
    uint32_t ttl = ((uint32_t) (wire->data[wire->pos]) << 24);
    ttl += ((uint32_t) wire->data[(wire->pos)+1]) << 16;
    ttl += ((uint32_t) wire->data[(wire->pos)+2]) << 8;
    ttl += (uint32_t) wire->data[(wire->pos)+3];

    wire->pos += DNS_TTL_SIZE;

    return ttl;
}


uint16_t get_rr_rdata_len(dns_wire *wire)
{
    uint16_t rdata_len = ((uint16_t) wire->data[wire->pos]) << 8;
    rdata_len += (uint16_t) wire->data[(wire->pos)+1];

    wire->pos += DNS_RDATA_LEN_SIZE;

    return rdata_len;
}


int get_rr_rdata(dns_wire *wire, uint16_t rdata_len, unsigned char **out)
{
    unsigned char *rdata = malloc(rdata_len);
    if (rdata == NULL)
        return EAI_MEMORY;

    memcpy(rdata, &wire->data[wire->pos], rdata_len);
    wire->pos += rdata_len;

    *out = rdata;
    return 0;
}


int get_ipv4_rdata(dns_wire *wire, uint16_t rdata_len, struct sockaddr **addr)
{
    struct sockaddr_in *ipv4_addr;

    if (rdata_len != sizeof(in_addr_t))
        return EAI_FAIL;

    ipv4_addr = calloc(1, sizeof(struct sockaddr_in));
    if (ipv4_addr == NULL)
        return EAI_MEMORY;

    ipv4_addr->sin_family = AF_INET;
    memcpy(&ipv4_addr->sin_addr.s_addr, &wire->data[wire->pos], rdata_len);

    wire->pos += rdata_len;

    *addr = (struct sockaddr*) ipv4_addr;
    return 0;
}


int get_ipv6_rdata(dns_wire *wire, uint16_t rdata_len, struct sockaddr **addr)
{
    struct sockaddr_in6 *ipv6_addr;

    if (rdata_len != sizeof(struct in6_addr))
        return EAI_FAIL;

    ipv6_addr = calloc(1, sizeof(struct sockaddr_in6));
    if (ipv6_addr == NULL)
        return EAI_MEMORY;

    ipv6_addr->sin6_family = AF_INET6;
    memcpy(&ipv6_addr->sin6_addr, &wire->data[wire->pos], rdata_len);

    wire->pos += rdata_len;

    *addr = (struct sockaddr*) ipv6_addr;
    return 0;
}


uint16_t get_header_id(unsigned char *header)
{
    uint16_t id = ((uint16_t) header[0]) << 8;
    id += (uint16_t) header[1];

    return id;
}

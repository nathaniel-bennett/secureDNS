#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "resource_records.h"
#include "dns_context.h"
#include "../include/dns.h"

#define MAX_HOSTNAME 255


#define HOSTNAME_WIRE_LEN(hostname) (strlen(hostname) + 2)

#define DNS_HEADER_BYTESIZE 12
#define DNS_TYPE_BYTESIZE 2
#define DNS_CLASS_BYTESIZE 2
#define DNS_TTL_BYTESIZE 4
#define DNS_RDATA_LEN_BYTESIZE 2

#define WIRE_QUERY_BYTESIZE(hostname) \
            (HOSTNAME_WIRE_LEN(hostname) + 4)

#define DNS_RECURSION_DESIRED_BIT 0x01

#define DNS_IN_CLASS 0x0001
#define DNS_A_TYPE 0x0001
#define DNS_AAAA_TYPE 0x001c
#define DNS_CNAME_TYPE 0x0005

#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_BAD_HOSTNAME 3


#define recursion_supported(wire) ((wire)[3] & 0x80 ? 1 : 0)
#define is_response_record(wire) ((wire)[2] & 0x80 ? 1 : 0)
#define is_truncated_record(wire) ((wire)[2] & 0x02 ? 1 : 0)

#define get_header_rcode(wire) ((wire)[3] & 0x0f)
#define get_header_opcode(wire) ((wire)[2] >> 3 & 0x0f)
#define get_question_cnt(wire) ((uint16_t) (((wire)[4] << 8) + (wire)[5]))
#define get_answer_rr_cnt(wire) ((uint16_t) (((wire)[6] << 8) + (wire)[7]))
#define get_authority_rr_cnt(wire) ((uint16_t) (((wire)[8] << 8) + (wire)[9]))
#define get_additional_rr_cnt(wire) (uint16_t) (((wire)[10] << 8) + (wire)[11])
#define get_rr_cnt(wire) (get_answer_rr_cnt(wire) \
            + get_authority_rr_cnt(wire) + get_additional_rr_cnt(wire))


int parse_dns_record(unsigned char *wire, int wire_len,
            int *pos, const char *hostname, uint16_t id, dns_rr **result);

int check_request_info(unsigned char *wire, int *pos, int wire_len,
            const char *hostname, uint16_t id);
int parse_query(unsigned char *wire, int *pos, int max_len, dns_rr **res);
int parse_rr(unsigned char *wire, int *pos, int wire_len, dns_rr **out);
dns_rr *concat_records(dns_rr *records, dns_rr *new_records);

void clear_header(unsigned char *wire);
void set_header_id(unsigned char *wire, uint16_t id);
void set_header_recursion_desired(unsigned char *wire);
void set_header_question_cnt(unsigned char *wire, uint16_t cnt);
uint16_t get_header_id(unsigned char *wire);
int check_dns_resp_header(unsigned char *wire, uint16_t id);

void set_rr_type(unsigned char *wire, int *pos, uint16_t type);
void set_rr_class(unsigned char *wire, int *pos, uint16_t class);
uint16_t get_rr_type(unsigned char *wire, int *pos);
uint16_t get_rr_class(unsigned char *wire, int *pos);
uint32_t get_rr_ttl(unsigned char *wire, int *pos);
uint16_t get_rr_rdata_len(unsigned char *wire, int *pos);
unsigned char *get_rr_rdata(unsigned char *wire, int *pos, uint16_t rdata_len);

int get_ipv4_rdata(unsigned char *wire,
                  int *pos, uint16_t len, struct sockaddr **addr);
int get_ipv6_rdata(unsigned char *wire,
                  int *pos, uint16_t len, struct sockaddr **addr);

void name_ascii_to_wire(unsigned char *wire, int *pos, const char *name);
int name_ascii_from_wire(unsigned char *wire,
                         int *pos, const int wire_len, char **out);



/*******************************************************************************
 *                  FUNCTIONS FOR RESOURCE RECORD CREATION
 ******************************************************************************/

int form_question_record(unsigned char *wire,
            ssize_t wire_size, uint16_t id, const char *hostname, int type)
{
    int query_len = 0;

    if (strlen(hostname) + 1 > MAX_HOSTNAME)
        return EAI_NONAME;

    if (wire_size < DNS_HEADER_BYTESIZE + WIRE_QUERY_BYTESIZE(hostname))
        return EAI_FAIL;

    /* header settings */
    clear_header(wire);
    set_header_id(wire, id);
    set_header_recursion_desired(wire);
    set_header_question_cnt(wire, 1);

    query_len = DNS_HEADER_BYTESIZE;

    name_ascii_to_wire(wire, &query_len, hostname);

    if (type == AF_INET)
        set_rr_type(wire, &query_len, DNS_A_TYPE);
    else /* (type == AF_INET6) */
        set_rr_type(wire, &query_len, DNS_AAAA_TYPE);

    set_rr_class(wire, &query_len, DNS_IN_CLASS);

    return query_len;
}

int parse_dns_records(unsigned char *wire,
            int wire_len, const char *hostname, uint16_t id, dns_rr **out)
{
    dns_rr *records = NULL, *tmp = NULL;
    int pos = 0, i, ret;

    /* we sent two queries: an A query and an AAAA query */
    for (i = 0; i < DNS_REQUEST_CNT; i++) {
        ret = parse_dns_record(wire, wire_len, &pos, hostname, id, &tmp);
        if (ret < 0)
            goto err;

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

int parse_dns_record(unsigned char *wire, int wire_len,
            int *pos, const char *hostname, uint16_t id, dns_rr **result)
{
    dns_rr *tmp = NULL;
    int i, ret;
    int record_cnt;
    char *cname = strdup(hostname);
    if (cname == NULL)
        return EAI_MEMORY;

    *result = NULL;

    record_cnt = check_request_info(wire, pos, wire_len, hostname, id);
    if (record_cnt < 0)
        goto err;

    for (i = 0; i < record_cnt; i++) {
        ret = parse_rr(wire, pos, wire_len, &tmp);
        if (ret != 0)
            goto err;

        if (tmp->is_other_type) {
            dns_records_free(tmp);
            continue;
        }

        if (strcmp(tmp->cname, cname) != 0) {
            ret = EAI_FAIL;
            goto err;
        }

        if (tmp->is_cname) {
            /* replace current cname with the new cname found in the record */
            free(cname);
            cname = tmp->aliased_host; /* we already converted from wire */
            tmp->aliased_host = NULL;

            dns_records_free(tmp);

        } else {
            free(tmp->cname);
            tmp->cname = strdup(cname);
            if (tmp->cname == NULL) {
                ret = EAI_MEMORY;
                goto err;
            }

            *result = concat_records(*result, tmp);
        }
    }

    free(cname);

    return 0;
err:
    if (*result != NULL)
        dns_records_free(*result);

    if (tmp != NULL && tmp != *result)
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
void name_ascii_to_wire(unsigned char *wire, int *pos, const char *name)
{
    int i = 0;
    uint8_t digit_cnt = 0;
    unsigned char *last = &wire[*pos];

    /* root name case */
    if (strcmp(name, ".") == 0) {
        wire[*pos] = '\0';
        *pos += 1;
        return;
    }

    while (name[i] != '\0') {

        if (name[i] == '.') {
            *last = digit_cnt;
            last = &wire[*pos+i+1];
            digit_cnt = 0;

        } else {
            wire[*pos+i+1] = name[i];
            digit_cnt++;
        }

        i++;
    }

    *last = digit_cnt;
    *pos += i+2;
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
int name_ascii_from_wire(unsigned char *wire,
                         int *pos, const int wire_len, char **out)
{
    unsigned char *curr = &wire[*pos];
    char buf[MAX_HOSTNAME];
    int i = 0, ret, buf_len;

    if (curr[0] == '\0') {
        *pos += 1; /* BUG: wire_len never checked here... */
        *out = strdup(".");
        if (*out == NULL)
            return EAI_MEMORY;
        return 0;
    }

    while (curr[i] != '\0' && curr[i] < 0xc0) {
        uint8_t word_len = curr[i];

        if (i != 0)
            buf[i-1] = '.';

        i += 1;

        /* catch buffer overflow */
        if ((i + word_len) >= MAX_HOSTNAME || (i + word_len) > wire_len)
            return EAI_FAIL;

        uint8_t c;
        for (c = 0; c < word_len; c++)
            buf[(i-1)+c] = curr[i+c];

        i += word_len;
    }

    /* compression case */
    if (curr[i] >= 192) {
        char *temp;
        int temp_len, offset;

        if ((i + 2) > wire_len)
            return EAI_FAIL;

        offset = ((int) curr[i] & ~0xc0) << 8;
        offset += (int) curr[i+1];

        ret = name_ascii_from_wire(wire, &offset, wire_len, &temp);
        if (ret != 0)
            return ret;

        temp_len = strlen(temp) + 1;

        if (i != 0)
            buf[i-1] = '.';

        if (i + temp_len > MAX_HOSTNAME) {
            free(temp);
            return EAI_FAIL;
        }

        memcpy(&buf[i], temp, temp_len);
        free(temp);

        i += 2;
    } else { /* curr[i] == '\0' */
        buf[i-1] = '\0';
        i += 1;
    }

    *pos += i;

    buf_len = strlen(buf) + 1;

    *out = (char*) malloc(buf_len);
    if (*out == NULL)
        return EAI_MEMORY;

    memcpy(*out, buf, buf_len);
    return 0;
}



/*******************************************************************************
 *                 HELPER FUNCTIONS FOR PARSING DNS RESPONSES
 ******************************************************************************/


int check_dns_resp_header(unsigned char *wire, uint16_t id)
{
    uint16_t resp_id = get_header_id(wire);
    if (resp_id != id)
        return -1;

    if (!is_response_record(wire))
        return EAI_FAIL;

    if (get_header_opcode(wire) != DNS_OPCODE_QUERY)
        return EAI_FAIL;

    if (is_truncated_record(wire))
        return EAI_FAIL;

    if (!recursion_supported(wire))
        return EAI_FAIL;

    if (get_header_rcode(wire) == DNS_RCODE_BAD_HOSTNAME)
        return EAI_NODATA;

    if (get_header_rcode(wire) != DNS_RCODE_NO_ERROR)
        return EAI_FAIL;


    if (get_question_cnt(wire) != 1)
        return EAI_FAIL;

    return 0;
}

int check_request_info(unsigned char *wire, int *pos, int wire_len,
            const char *hostname, uint16_t id)
{
    int record_cnt, ret;
    dns_rr *tmp;

    if (wire_len - *pos < DNS_HEADER_BYTESIZE)
        return EAI_FAIL;

    ret = check_dns_resp_header(&wire[*pos], id);
    if (ret != 0)
        return ret;

    record_cnt = get_rr_cnt(&wire[*pos]);
    *pos += DNS_HEADER_BYTESIZE;

    ret = parse_query(wire, pos, wire_len, &tmp);
    if (ret != 0)
        return ret;

    if (strcmp(tmp->cname, hostname) != 0) {
        dns_records_free(tmp);
        return EAI_FAIL;
    }

    dns_records_free(tmp);
    return record_cnt;
}

int parse_query(unsigned char *wire, int *pos, int wire_len, dns_rr **res)
{
    int ret;

    dns_rr *record = calloc(1, sizeof(dns_rr));
    if (record == NULL)
        return EAI_MEMORY;

    /* extract name from wire */
    ret = name_ascii_from_wire(wire, pos, wire_len, &record->cname);
    if (record->cname == NULL)
        goto err;

    /* extract type from wire */
    uint16_t type = get_rr_type(wire, pos);
    if (type != DNS_A_TYPE && type != DNS_AAAA_TYPE) {
        ret = EAI_FAIL;
        goto err;
    }

    uint16_t class = get_rr_class(wire, pos);
    if (class != DNS_IN_CLASS) {
        ret = EAI_FAIL;
        goto err;
    }

    *res = record;
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
int parse_rr(unsigned char *wire, int *pos, int wire_len, dns_rr **out)
{
    int ret;

    dns_rr *record = calloc(1, sizeof(dns_rr));
    if (record == NULL)
        return EAI_MEMORY;

    /* extract name from wire */
    ret = name_ascii_from_wire(wire, pos, wire_len, &record->cname);
    if (ret != 0)
        goto err;

    /* extract type from wire */

    if ((*pos + DNS_TYPE_BYTESIZE + DNS_CLASS_BYTESIZE
        + DNS_TTL_BYTESIZE + DNS_RDATA_LEN_BYTESIZE) > wire_len) {
        ret = EAI_FAIL;
        goto err;
    }

    uint16_t type = get_rr_type(wire, pos);
    uint16_t class = get_rr_class(wire, pos);
    if (class != DNS_IN_CLASS) {
        ret = EAI_FAIL;
        goto err;
    }

    /* if time(NULL) returns -1 then it will just expire sooner */
    record->ttl = time(NULL) + (time_t)get_rr_ttl(wire, pos);

    record->resp_len = get_rr_rdata_len(wire, pos);
    if (*pos + record->resp_len > wire_len) {
        ret = EAI_FAIL;
        goto err;
    }


    if (type == DNS_CNAME_TYPE) {
        record->is_cname = 1;
        ret = name_ascii_from_wire(wire,
                    pos, wire_len, &record->aliased_host);

    } else if (type == DNS_A_TYPE) {
        ret = get_ipv4_rdata(wire,
                             pos, record->resp_len, &record->addr);

    } else if (type == DNS_AAAA_TYPE) {
        ret = get_ipv6_rdata(wire,
                             pos, record->resp_len, &record->addr);

    } else {
        record->is_other_type = 1;
        record->data = get_rr_rdata(wire, pos, record->resp_len);
        if (record->data == NULL)
            ret = EAI_MEMORY;
    }

    if (ret != 0)
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

void clear_header(unsigned char *wire)
{
    memset(wire, 0, DNS_HEADER_BYTESIZE);
}

void set_header_id(unsigned char *wire, uint16_t id)
{
    wire[0] = id >> 8;
    wire[1] = id & 0xff;
}

void set_header_recursion_desired(unsigned char *wire)
{
    wire[2] |= DNS_RECURSION_DESIRED_BIT;
}

void set_header_question_cnt(unsigned char *wire, uint16_t cnt)
{
    wire[4] = cnt >> 8;
    wire[5] = cnt & 0xff;
}

void set_rr_type(unsigned char *wire, int *pos, uint16_t type)
{
    wire[*pos] = type >> 8;
    wire[*pos+1] = type & 0xff;

    *pos += DNS_TYPE_BYTESIZE;
}

void set_rr_class(unsigned char *wire, int *pos, uint16_t class)
{
    wire[*pos] = class >> 8;
    wire[*pos+1] = class & 0xff;

    *pos += DNS_CLASS_BYTESIZE;
}

/*******************************************************************************
 *           FUNCTIONS TO RETRIEVE INFO FROM THE RESOURCE RECORD
 ******************************************************************************/

uint16_t get_rr_type(unsigned char *wire, int *pos)
{
    uint16_t type = ((uint16_t) wire[*pos]) << 8;
    type += (uint16_t) wire[*pos+1];

    *pos += DNS_TYPE_BYTESIZE;

    return type;
}

uint16_t get_rr_class(unsigned char *wire, int *pos)
{
    uint16_t class = ((uint16_t) wire[*pos]) << 8;
    class += (uint16_t) wire[*pos+1];

    *pos += DNS_CLASS_BYTESIZE;

    return class;
}

uint32_t get_rr_ttl(unsigned char *wire, int *pos)
{
    uint32_t ttl = ((uint32_t) (wire[*pos]) << 24);
    ttl += ((uint32_t) wire[(*pos)+1]) << 16;
    ttl += ((uint32_t) wire[(*pos)+2]) << 8;
    ttl += (uint32_t) (wire[(*pos)+3]);

    *pos += DNS_TTL_BYTESIZE;

    return ttl;
}

uint16_t get_rr_rdata_len(unsigned char *wire, int *pos)
{
    uint16_t rdata_len = ((uint16_t) wire[*pos]) << 8;
    rdata_len += (uint16_t) wire[(*pos)+1];

    *pos += DNS_RDATA_LEN_BYTESIZE;

    return rdata_len;
}

unsigned char *get_rr_rdata(unsigned char *wire, int *pos, uint16_t rdata_len)
{
    unsigned char *rdata = malloc(rdata_len);
    if (rdata == NULL)
        return NULL;

    memcpy(rdata, &wire[*pos], rdata_len);
    *pos += rdata_len;

    return rdata;
}

int get_ipv4_rdata(unsigned char *wire,
    int *pos, uint16_t len, struct sockaddr **addr)
{
    struct sockaddr_in *ipv4_addr;

    if (len != sizeof(in_addr_t))
        return EAI_FAIL;

    ipv4_addr = calloc(1, sizeof(struct sockaddr_in));
    if (ipv4_addr == NULL)
        return EAI_MEMORY;

    ipv4_addr->sin_family = AF_INET;

    memcpy(&ipv4_addr->sin_addr.s_addr, &wire[*pos], len);

    *addr = (struct sockaddr*) ipv4_addr;
    *pos += len;

    return 0;
}

int get_ipv6_rdata(unsigned char *wire,
    int *pos, uint16_t len, struct sockaddr **addr)
{
    struct sockaddr_in6 *ipv6_addr;

    if (len != sizeof(struct in6_addr))
        return EAI_FAIL;

    ipv6_addr = calloc(1, sizeof(struct sockaddr_in6));
    if (ipv6_addr == NULL)
        return EAI_MEMORY;

    ipv6_addr->sin6_family = AF_INET6;
    memcpy(&ipv6_addr->sin6_addr, &wire[*pos], len);

    *addr = (struct sockaddr*) ipv6_addr;
    *pos += len;

    return 0;
}

uint16_t get_header_id(unsigned char *wire)
{
    uint16_t id = ((uint16_t) wire[0]) << 8;
    id += (uint16_t) wire[1];

    return id;
}



/*
dns_rr *clear_expired_records(dns_rr *root)
{
    dns_rr *curr, *prev;
    time_t curr_time = time(NULL);

    if (root == NULL)
        return NULL;

    if (curr_time == -1) {
        dns_records_free(root);
        return NULL;
    }

    while (root != NULL && curr_time > root->ttl) {
        curr = root->next;
        root->next = NULL;

        dns_records_free(root);
        root = curr;
    }

    if (root == NULL)
        return NULL;

    prev = root;
    curr = root->next;

    while (curr != NULL) {
        if (curr_time > curr->ttl) {
            prev->next = curr->next;
            curr->next = NULL;

            dns_records_free(curr);
            curr = prev->next;
        } else {
            prev = curr;
            curr = curr->next;
        }
    }

    return root;
}
 */


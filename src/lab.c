#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL || addr == NULL)
  {
    return false;
  }

  const unsigned char *cursor = (const unsigned char *) text;
  uint32_t parsed = 0;

  for (unsigned int octet = 0; octet < 4; octet++)
  {
    if (*cursor < '0' || *cursor > '9')
    {
      return false;
    }

    if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9')
    {
      return false;
    }

    unsigned int value = 0;
    while (*cursor >= '0' && *cursor <= '9')
    {
      value = value * 10U + (unsigned int) (*cursor - '0');
      if (value > 255U)
      {
        return false;
      }
      cursor++;
    }

    parsed = (parsed << 8) | (uint32_t) value;
    if (octet < 3)
    {
      if (*cursor != '.')
      {
        return false;
      }
      cursor++;
    }
    else if (*cursor != '\0')
    {
      return false;
    }
  }

  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void) snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                  (unsigned int) ((addr >> 24) & UINT32_C(0xff)),
                  (unsigned int) ((addr >> 16) & UINT32_C(0xff)),
                  (unsigned int) ((addr >> 8) & UINT32_C(0xff)),
                  (unsigned int) (addr & UINT32_C(0xff)));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL)
  {
    return false;
  }

  const char *slash = text;
  while (*slash != '\0' && *slash != '/')
  {
    slash++;
  }
  if (*slash != '/')
  {
    return false;
  }

  size_t address_length = (size_t) (slash - text);
  if (address_length == 0 || address_length >= IP_STR_LEN)
  {
    return false;
  }

  char address[IP_STR_LEN];
  for (size_t i = 0; i < address_length; i++)
  {
    address[i] = text[i];
  }
  address[address_length] = '\0';

  const unsigned char *cursor = (const unsigned char *) (slash + 1);
  if (*cursor < '0' || *cursor > '9')
  {
    return false;
  }
  if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9')
  {
    return false;
  }

  unsigned int prefix = 0;
  while (*cursor >= '0' && *cursor <= '9')
  {
    prefix = prefix * 10U + (unsigned int) (*cursor - '0');
    if (prefix > 32U)
    {
      return false;
    }
    cursor++;
  }
  if (*cursor != '\0')
  {
    return false;
  }

  uint32_t parsed_address;
  if (!ip_parse(address, &parsed_address))
  {
    return false;
  }

  block->addr = parsed_address;
  block->prefix = (uint8_t) prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  unsigned int prefix = block.prefix > 32U ? 32U : (unsigned int) block.prefix;
  (void) snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0)
  {
    return 0;
  }
  if (prefix > 32)
  {
    prefix = 32;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  uint32_t mask = cidr_mask(block.prefix);
  return cidr_network(block) | ~mask;
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return block.prefix <= 30 ? network + 1U : network;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return block.prefix <= 30 ? broadcast - 1U : broadcast;
}

uint64_t cidr_host_count(cidr_t block)
{
  unsigned int prefix = block.prefix > 32 ? 32U : (unsigned int) block.prefix;
  if (prefix == 32)
  {
    return 1;
  }
  if (prefix == 31)
  {
    return 2;
  }
  return (UINT64_C(1) << (32U - prefix)) - 2U;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == cidr_network(block);
}

bool cidr_is_network(cidr_t block)
{
  return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || block.prefix > 32 || !cidr_is_network(block)
      || n == 0 || (n & (n - 1U)) != 0 || i >= n)
  {
    return false;
  }

  unsigned int borrowed = 0;
  for (uint32_t parts = n; parts > 1; parts >>= 1)
  {
    borrowed++;
  }
  unsigned int new_prefix = (unsigned int) block.prefix + borrowed;
  if (new_prefix > 32)
  {
    return false;
  }

  unsigned int host_bits = 32U - new_prefix;
  uint64_t offset = (uint64_t) i << host_bits;
  cidr_t subnet = {
    block.addr + (uint32_t) offset,
    (uint8_t) new_prefix
  };
  *out = subnet;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL || route == NULL)
  {
    return false;
  }

  const char *cursor = line;
  const char *fields[3];
  size_t lengths[3];

  for (size_t field = 0; field < 3; field++)
  {
    while (*cursor == ' ' || *cursor == '\t')
    {
      cursor++;
    }
    if (*cursor == '\0' || *cursor == '\n' || *cursor == '\r')
    {
      return false;
    }

    fields[field] = cursor;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t'
           && *cursor != '\n' && *cursor != '\r')
    {
      cursor++;
    }
    lengths[field] = (size_t) (cursor - fields[field]);
  }

  while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n'
         || *cursor == '\r')
  {
    cursor++;
  }
  if (*cursor != '\0' || lengths[2] >= DEV_NAME_LEN)
  {
    return false;
  }

  route_t parsed = { 0 };
  if (lengths[0] == sizeof("default") - 1
      && memcmp(fields[0], "default", sizeof("default") - 1) == 0)
  {
    parsed.dest.addr = 0;
    parsed.dest.prefix = 0;
  }
  else
  {
    char destination[CIDR_STR_LEN];
    if (lengths[0] >= sizeof(destination))
    {
      return false;
    }
    memcpy(destination, fields[0], lengths[0]);
    destination[lengths[0]] = '\0';
    if (!cidr_parse(destination, &parsed.dest)
        || !cidr_is_network(parsed.dest))
    {
      return false;
    }
  }

  if (lengths[1] == sizeof("direct") - 1
      && memcmp(fields[1], "direct", sizeof("direct") - 1) == 0)
  {
    parsed.gateway = 0;
  }
  else
  {
    char gateway[IP_STR_LEN];
    if (lengths[1] >= sizeof(gateway))
    {
      return false;
    }
    memcpy(gateway, fields[1], lengths[1]);
    gateway[lengths[1]] = '\0';
    if (!ip_parse(gateway, &parsed.gateway))
    {
      return false;
    }
  }

  memcpy(parsed.dev, fields[2], lengths[2]);
  parsed.dev[lengths[2]] = '\0';
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL)
  {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || route->dest.prefix > 32
      || !cidr_is_network(route->dest))
  {
    return false;
  }

  size_t new_capacity = table->capacity;
  if (table->count == table->capacity)
  {
    size_t max_capacity = SIZE_MAX / sizeof(*table->routes);
    if (table->capacity == 0)
    {
      new_capacity = 8;
    }
    else
    {
      if (table->capacity > max_capacity / 2)
      {
        return false;
      }
      new_capacity = table->capacity * 2;
    }
  }

  for (size_t i = 0; i < table->count; i++)
  {
    if (table->routes[i].dest.addr == route->dest.addr
        && table->routes[i].dest.prefix == route->dest.prefix)
    {
      return false;
    }
  }

  if (table->count == table->capacity)
  {
    route_t *routes = realloc(table->routes, new_capacity * sizeof(*routes));
    if (routes == NULL) // GCOVR_EXCL_BR_LINE
    {
      return false; // GCOVR_EXCL_LINE
    }
    table->routes = routes;
    table->capacity = new_capacity;
  }

  table->routes[table->count++] = *route;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  ssize_t line_length;
  while ((line_length = getline(&line, &capacity, in)) != -1)
  {
    line_number++;
    char *comment = strchr(line, '#');
    if (comment != NULL)
    {
      *comment = '\0';
    }

    const char *content = line;
    while (*content == ' ' || *content == '\t' || *content == '\n'
           || *content == '\r')
    {
      content++;
    }
    if (*content != '\0')
    {
      route_t route;
      if (!route_parse(content, &route) || !table_add(table, &route))
      {
        if (bad_line != NULL)
        {
          *bad_line = line_number;
        }
        free(line);
        return false;
      }
    }
  }

  free(line);
  if (ferror(in)) // GCOVR_EXCL_BR_LINE
  {
    return false; // GCOVR_EXCL_LINE
  }
  return feof(in) != 0; // GCOVR_EXCL_BR_LINE
}

#ifdef TEST
void table_test_set_full_capacity(fwd_table_t *table, size_t capacity)
{
  table->count = capacity;
  table->capacity = capacity;
}
#endif

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL)
  {
    return NULL;
  }

  const route_t *best = NULL;
  for (size_t i = 0; i < table->count; i++)
  {
    const route_t *route = &table->routes[i];
    if (cidr_contains(route->dest, dest)
        && (best == NULL || route->dest.prefix > best->dest.prefix))
    {
      best = route;
    }
  }
  return best;
}

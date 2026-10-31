#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *stream)
{
  (void) fprintf(stream,
                 "Usage: myapp info <address>/<prefix>\n"
                 "       myapp split <network>/<prefix> <count>\n"
                 "       myapp lookup <table-file> <address>...\n");
}

static bool parse_count(const char *text, uint32_t *count)
{
  if (text == NULL || count == NULL || *text == '\0')
  {
    return false;
  }

  uint32_t parsed = 0;
  const unsigned char *cursor = (const unsigned char *) text;
  while (*cursor >= '0' && *cursor <= '9')
  {
    uint32_t digit = (uint32_t) (*cursor - '0');
    if (parsed > (UINT32_MAX - digit) / 10U)
    {
      return false;
    }
    parsed = parsed * 10U + digit;
    cursor++;
  }
  if (*cursor != '\0')
  {
    return false;
  }

  *count = parsed;
  return true;
}

static int run_info(const char *text)
{
  cidr_t block;
  if (!cidr_parse(text, &block))
  {
    (void) fprintf(stderr, "myapp: %s: not a valid address/prefix\n", text);
    return 1;
  }

  char address[IP_STR_LEN];
  char mask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), mask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);

  (void) printf("address    %s\n"
                "prefix     /%u\n"
                "netmask    %s\n"
                "network    %s\n"
                "broadcast  %s\n"
                "first host %s\n"
                "last host  %s\n"
                "hosts      %" PRIu64 "\n",
                address, (unsigned int) block.prefix, mask, network,
                broadcast, first_host, last_host, cidr_host_count(block));
  return 0;
}

static int run_split(const char *text, const char *count_text)
{
  cidr_t block;
  if (!cidr_parse(text, &block))
  {
    (void) fprintf(stderr, "myapp: %s: not a valid network/prefix\n", text);
    return 1;
  }

  uint32_t count;
  if (!parse_count(count_text, &count) || count == 0
      || (count & (count - 1U)) != 0)
  {
    (void) fprintf(stderr, "myapp: %s: count must be a positive power of two\n",
                   count_text);
    return 1;
  }
  if (!cidr_is_network(block))
  {
    (void) fprintf(stderr, "myapp: %s: block has host bits set\n", text);
    return 1;
  }

  for (uint32_t i = 0; i < count; i++)
  {
    cidr_t subnet;
    if (!cidr_subnet(block, count, i, &subnet))
    {
      (void) fprintf(stderr,
                     "myapp: cannot split %s into %" PRIu32 " subnets\n",
                     text, count);
      return 1;
    }
    char formatted[CIDR_STR_LEN];
    cidr_format(subnet, formatted);
    (void) puts(formatted);
  }
  return 0;
}

static int run_lookup(const char *path, int address_count, char *const addresses[])
{
  FILE *input = fopen(path, "r");
  if (input == NULL)
  {
    (void) fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return 2;
  }

  fwd_table_t *table = table_create();
  if (table == NULL)
  {
    (void) fprintf(stderr, "myapp: could not allocate forwarding table\n");
    (void) fclose(input);
    return 2;
  }

  size_t bad_line = 0;
  if (!table_load(table, input, &bad_line))
  {
    if (bad_line != 0)
    {
      (void) fprintf(stderr, "myapp: %s:%zu: not a valid route\n",
                     path, bad_line);
    }
    else
    {
      (void) fprintf(stderr, "myapp: %s: could not read table\n", path);
    }
    table_destroy(table);
    (void) fclose(input);
    return 2;
  }
  (void) fclose(input);

  int exit_status = 0;
  for (int i = 0; i < address_count; i++)
  {
    uint32_t address;
    if (!ip_parse(addresses[i], &address))
    {
      (void) fprintf(stderr, "myapp: %s: not a valid address\n", addresses[i]);
      exit_status = 1;
      continue;
    }

    char formatted_address[IP_STR_LEN];
    ip_format(address, formatted_address);
    const route_t *route = table_lookup(table, address);
    if (route == NULL)
    {
      (void) printf("%s unreachable\n", formatted_address);
      if (exit_status == 0)
      {
        exit_status = 3;
      }
    }
    else if (route->gateway == 0)
    {
      (void) printf("%s dev %s\n", formatted_address, route->dev);
    }
    else
    {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      (void) printf("%s via %s dev %s\n",
                    formatted_address, gateway, route->dev);
    }
  }

  table_destroy(table);
  return exit_status;
}

int main(int argc, char *argv[])
{
  if (argc == 1)
  {
    print_usage(stdout);
    return 0;
  }

  if (strcmp(argv[1], "info") == 0)
  {
    if (argc != 3)
    {
      print_usage(stderr);
      return 1;
    }
    return run_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0)
  {
    if (argc != 4)
    {
      print_usage(stderr);
      return 1;
    }
    return run_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0)
  {
    if (argc < 4)
    {
      print_usage(stderr);
      return 1;
    }
    return run_lookup(argv[2], argc - 3, &argv[3]);
  }

  (void) fprintf(stderr, "myapp: unknown command: %s\n", argv[1]);
  print_usage(stderr);
  return 1;
}

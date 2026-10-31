#include "harness/unity.h"
#include "../src/lab.h"

void table_test_set_full_capacity(fwd_table_t *table, size_t capacity);

void setUp(void) {}
void tearDown(void) {}

void test_ip_parse_and_format(void) {
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
    "1.2.3.4x", "+1.2.3.4", "1.2.3.4 ", "x.0.0.0", ":.0.0.0",
    "00.0.0.0", "0x.0.0.0", "1x.2.3.4", "1.2.3.4."
  };
  uint32_t addr = UINT32_C(0xdeadbeef);

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a8010a), addr);
  char formatted[IP_STR_LEN];
  ip_format(addr, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", formatted);

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    addr = UINT32_C(0xdeadbeef);
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xdeadbeef), addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_cidr_parse_and_format(void) {
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
    "1.2.3.4x", "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",
    "1.2.3/24", "1.2.3.4/+24", "1.2.3.4/24x", "1.2.3.4/24/1",
    "/24", "1234567890123456/24", "1.2.3.4/:24", "1.2.3.4/00",
    "1.2.3.4/0x"
  };
  cidr_t block = { UINT32_C(0xdeadbeef), 7 };

  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e30b), block.addr);
  TEST_ASSERT_EQUAL_UINT8(25, block.prefix);
  char formatted[CIDR_STR_LEN];
  cidr_format(block, formatted);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", formatted);

  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT32(0, block.addr);
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    block.addr = UINT32_C(0xdeadbeef);
    block.prefix = 7;
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xdeadbeef), block.addr);
    TEST_ASSERT_EQUAL_UINT8(7, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));

  block.addr = UINT32_C(0xc0a8010a);
  block.prefix = 33;
  cidr_format(block, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10/32", formatted);
}

void test_cidr_subnet_arithmetic(void) {
  TEST_ASSERT_EQUAL_UINT32(0, cidr_mask(0));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xffffff00), cidr_mask(24));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_mask(33));

  cidr_t block = { UINT32_C(0x84b2e30b), 25 };
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e300), cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e37f), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e301), cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e37e), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84b2e300)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84b2e37f)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x84b2e380)));
  TEST_ASSERT_FALSE(cidr_is_network(block));
  block.addr = UINT32_C(0x84b2e300);
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = 0;
  block.prefix = 0;
  TEST_ASSERT_EQUAL_UINT32(0, cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(1, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX - 1U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));

  block.addr = UINT32_C(0xc0a80101);
  block.prefix = 30;
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80100), cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80103), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80101), cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80102), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block));

  block.addr = UINT32_C(0xc0a80100);
  block.prefix = 31;
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80100), cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80101), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block));
  block.prefix = 32;
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80100), cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80100), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));

  cidr_t subnet;
  block.addr = UINT32_C(0xc0a80100);
  block.prefix = 24;
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a80100), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xc0a801c0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);

  block.addr = 0;
  block.prefix = 0;
  TEST_ASSERT_TRUE(cidr_subnet(block, UINT32_C(0x80000000),
                               UINT32_C(0x7fffffff), &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xfffffffe), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(31, subnet.prefix);

  subnet.addr = UINT32_C(0xdeadbeef);
  subnet.prefix = 7;
  block.addr = UINT32_C(0xc0a80101);
  block.prefix = 24;
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xdeadbeef), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(7, subnet.prefix);
  block.addr = UINT32_C(0xc0a80100);
  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 512, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, NULL));
  block.prefix = 33;
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, &subnet));
}

void test_route_parse(void) {
  route_t route = {
    { UINT32_C(0xdeadbeef), 7 },
    UINT32_C(0x12345678),
    "unchanged"
  };
  TEST_ASSERT_TRUE(route_parse("  10.1.2.0/24\tdirect\teth2 \t\r\n", &route));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0a010200), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(24, route.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", route.dev);

  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1", &route));
  TEST_ASSERT_EQUAL_UINT32(0, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  const char *invalid[] = {
    "10.1.2.1/24 direct eth0", "10.1.2.0/24 010.0.0.1 eth0",
    "10.1.2.0/24 direct", "10.1.2.0/24 direct eth0 extra",
    "10.1.2.0/24 direct eth0123456789012", "", "\n", "\r",
    "default\n direct eth0", "default\r direct eth0",
    "garbage direct eth0",
    "12345678901234567890 direct eth0",
    "default 1.1.1. eth0",
    "default 1234567890123456 eth0"
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    route_t unchanged = route;
    TEST_ASSERT_FALSE(route_parse(invalid[i], &route));
    TEST_ASSERT_EQUAL_UINT32(unchanged.dest.addr, route.dest.addr);
    TEST_ASSERT_EQUAL_UINT8(unchanged.dest.prefix, route.dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(unchanged.gateway, route.gateway);
    TEST_ASSERT_EQUAL_STRING(unchanged.dev, route.dev);
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

void test_forwarding_table(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_UINT32(0, table_count(table));
  TEST_ASSERT_EQUAL_UINT32(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, 0));

  route_t route;
  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_UINT32(1, table_count(table));

  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 10.1.0.1 eth1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 direct eth1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth2", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.2.128/25 10.1.2.1 eth2", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  const route_t *found = table_lookup(table, UINT32_C(0x0a0102c8));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(25, found->dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0a010201), found->gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", found->dev);
  found = table_lookup(table, UINT32_C(0x0a010205));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(24, found->dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(0, found->gateway);
  found = table_lookup(table, UINT32_C(0x08080808));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(0, found->dest.prefix);

  fwd_table_t *reverse_table = table_create();
  TEST_ASSERT_NOT_NULL(reverse_table);
  TEST_ASSERT_TRUE(route_parse("10.2.0.0/16 direct eth1", &route));
  TEST_ASSERT_TRUE(table_add(reverse_table, &route));
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 10.1.0.1 eth1", &route));
  TEST_ASSERT_TRUE(table_add(reverse_table, &route));
  found = table_lookup(reverse_table, UINT32_C(0x0a020001));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(16, found->dest.prefix);
  table_destroy(reverse_table);

  route.dest.addr = UINT32_C(0x0a000001);
  route.dest.prefix = 24;
  TEST_ASSERT_FALSE(table_add(table, &route));
  route.dest.addr = UINT32_C(0x0a000000);
  route.dest.prefix = 9;
  TEST_ASSERT_TRUE(table_add(table, &route));
  route.dest.addr = UINT32_C(0x0a000000);
  route.dest.prefix = 33;
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_FALSE(table_add(NULL, &route));
  TEST_ASSERT_EQUAL_UINT32(6, table_count(table));
  table_destroy(table);
  table_destroy(NULL);

  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(route_parse("192.0.2.0/24 direct eth0", &route));
  table_test_set_full_capacity(
    table, (SIZE_MAX / sizeof(route_t)) / 2U + 1U);
  TEST_ASSERT_FALSE(table_add(table, &route));
  table_destroy(table);

  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  for (uint32_t i = 0; i < 20; i++) {
    route.dest.addr = UINT32_C(0xc0000200) + i;
    route.dest.prefix = 32;
    route.gateway = 0;
    (void) snprintf(route.dev, sizeof(route.dev), "d%u", (unsigned int) i);
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_UINT32(20, table_count(table));
  found = table_lookup(table, UINT32_C(0xc000020b));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_STRING("d11", found->dev);
  table_destroy(table);
}

void test_table_load(void) {
  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("\n \t# blank table\n\r# carriage return blank\n",
                         input) >= 0);
  rewind(input);
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0, bad_line);
  TEST_ASSERT_EQUAL_UINT32(0, table_count(table));
  fclose(input);
  table_destroy(table);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("192.0.2.0/24 direct eth0", input) >= 0);
  rewind(input);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(table_load(table, input, NULL));
  TEST_ASSERT_EQUAL_UINT32(1, table_count(table));
  fclose(input);
  table_destroy(table);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("# routes\n\n default 132.178.227.1 eno1\n"
                         "10.0.0.0/8 direct eth1 # local\n", input) >= 0);
  rewind(input);

  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0, bad_line);
  TEST_ASSERT_EQUAL_UINT32(2, table_count(table));
  TEST_ASSERT_NOT_NULL(table_lookup(table, UINT32_C(0x0a010203)));
  fclose(input);
  table_destroy(table);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("# routes\n default direct eno1\n"
                         "10.0.0.0/8 direct eth1\n"
                         "10.0.0.0/8 1.1.1.1 eth2\n", input) >= 0);
  rewind(input);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(4, bad_line);
  TEST_ASSERT_EQUAL_UINT32(2, table_count(table));
  fclose(input);
  table_destroy(table);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("invalid route\n", input) >= 0);
  rewind(input);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_FALSE(table_load(table, input, NULL));
  fclose(input);
  table_destroy(table);

  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(NULL, stdin, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0, bad_line);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0, bad_line);
  table_destroy(table);
  TEST_ASSERT_FALSE(table_load(NULL, NULL, NULL));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_and_format);
  RUN_TEST(test_cidr_subnet_arithmetic);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_forwarding_table);
  RUN_TEST(test_table_load);
  return UNITY_END();
}

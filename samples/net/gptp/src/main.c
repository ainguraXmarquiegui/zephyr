/*
 * Copyright (c) 2018 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_gptp_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <errno.h>

#include <net/net_core.h>
#include <net/net_l2.h>
#include <net/net_if.h>
#include <net/ethernet.h>
#include <net/gptp.h>

/*USER BEGIN INCLUDES*/
#include <net/ptp_time.h>
#include <sys/printk.h>
#include <sys/util.h>
/*USER END INCLUDES*/

extern void init_testing(void);

static struct gptp_phase_dis_cb phase_dis;

/*USER BEGIN VARIABLES*/
static struct net_ptp_time slave_time;
//struct gptp_clk_src_time_invoke_params src_time_invoke_parameters;
bool gm_present;
int status;
/*USER END VARIABLES*/

#if defined(CONFIG_NET_GPTP_VLAN)
/* User data for the interface callback */
struct ud {
	struct net_if *first;
	struct net_if *second;
	struct net_if *third;
};

static void iface_cb(struct net_if *iface, void *user_data)
{
	struct ud *ud = user_data;

	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return;
	}

	if (!ud->first) {
		ud->first = iface;
		return;
	}

	if (!ud->second) {
		ud->second = iface;
		return;
	}

	if (!ud->third) {
		ud->third = iface;
		return;
	}
}

static int setup_iface(struct net_if *iface, const char *ipv6_addr,
		       const char *ipv4_addr, uint16_t vlan_tag)
{
	struct net_if_addr *ifaddr;
	struct in_addr addr4;
	struct in6_addr addr6;
	int ret;

	ret = net_eth_vlan_enable(iface, vlan_tag);
	if (ret < 0) {
		LOG_ERR("Cannot enable VLAN for tag %d (%d)", vlan_tag, ret);
	}

	if (net_addr_pton(AF_INET6, ipv6_addr, &addr6)) {
		LOG_ERR("Invalid address: %s", ipv6_addr);
		return -EINVAL;
	}

	ifaddr = net_if_ipv6_addr_add(iface, &addr6, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		LOG_ERR("Cannot add %s to interface %p", ipv6_addr, iface);
		return -EINVAL;
	}

	if (net_addr_pton(AF_INET, ipv4_addr, &addr4)) {
		LOG_ERR("Invalid address: %s", ipv4_addr);
		return -EINVAL;
	}

	ifaddr = net_if_ipv4_addr_add(iface, &addr4, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		LOG_ERR("Cannot add %s to interface %p", ipv4_addr, iface);
		return -EINVAL;
	}

	LOG_DBG("Interface %p VLAN tag %d setup done.", iface, vlan_tag);

	return 0;
}

static int init_vlan(void)
{
	struct ud ud;
	int ret;

	(void)memset(&ud, 0, sizeof(ud));

	net_if_foreach(iface_cb, &ud);

	/* This sample has two VLANs. For the second one we need to manually
	 * create IP address for this test. But first the VLAN needs to be
	 * added to the interface so that IPv6 DAD can work properly.
	 */
	ret = setup_iface(ud.second,
			  CONFIG_NET_SAMPLE_IFACE2_MY_IPV6_ADDR,
			  CONFIG_NET_SAMPLE_IFACE2_MY_IPV4_ADDR,
			  CONFIG_NET_SAMPLE_IFACE2_VLAN_TAG);
	if (ret < 0) {
		return ret;
	}

	ret = setup_iface(ud.third,
			  CONFIG_NET_SAMPLE_IFACE3_MY_IPV6_ADDR,
			  CONFIG_NET_SAMPLE_IFACE3_MY_IPV4_ADDR,
			  CONFIG_NET_SAMPLE_IFACE3_VLAN_TAG);
	if (ret < 0) {
		return ret;
	}

	return 0;
}
#endif /* CONFIG_NET_GPTP_VLAN */

static void gptp_phase_dis_cb(uint8_t *gm_identity,
			      uint16_t *time_base,
			      struct gptp_scaled_ns *last_gm_ph_change,
			      double *last_gm_freq_change)
{
	char output[sizeof("xx:xx:xx:xx:xx:xx:xx:xx")];
	static uint8_t id[8];

	if (memcmp(id, gm_identity, sizeof(id))) {
		memcpy(id, gm_identity, sizeof(id));

		LOG_DBG("GM %s last phase %d.%" PRId64 "",
			log_strdup(gptp_sprint_clock_id(gm_identity, output,
							sizeof(output))),
			last_gm_ph_change->high,
			last_gm_ph_change->low);
	}
}

static int init_app(void)
{
#if defined(CONFIG_NET_GPTP_VLAN)
	if (init_vlan() < 0) {
		LOG_ERR("Cannot setup VLAN");
	}
#endif

	gptp_register_phase_dis_cb(&phase_dis, gptp_phase_dis_cb);

	return 0;
}

void main(void)
{
	int32_t max_lapse_diff_ns = 0, min_lapse_diff_ns = 0;
	int64_t lapse_diff_ns;
	uint64_t current_timelapse_ns;
	uint32_t looptime_ms;
	uint64_t prevsecond = 0;
    uint64_t prevnanosecond = 0;
	uint32_t lapse_diff_err_ns, lapse_diff_err_count = 0;
	uint32_t report_loops, report_loop = 0;
	int32_t numbertest;

    init_app();
    init_testing();

	/* Configurable parameters */
	looptime_ms = 593; /* Time to sleep for between test loops. In Miliseconds */
	lapse_diff_err_ns = 5000000; /* Loop difference threshold to signal an error, in nanoseconds */

	/* Prepare test loop */	
	min_lapse_diff_ns = looptime_ms * 1000000;
	/* We want preiodic reports coming no faster than 1second apart */
	if (looptime_ms >= 1000) {
		report_loops = 1;
	} else {
		report_loops = 1000 / looptime_ms;
	}

	/* Verify the compiler maximum and minimum values to verify that
	we are comparing limits correctly further on */
	LOG_INF("BEGIN NUMBERTEST");
	numbertest = 0x0;
	LOG_INF("NUMBERTEST 0x0: %d, 0x%X", numbertest, numbertest);
	numbertest = 0xFFFFFFFF;
	LOG_INF("NUMBERTEST 0xFFFFFFFF: %d, 0x%X", numbertest, numbertest);
	numbertest = 0x80000000;
	LOG_INF("NUMBERTEST 0x80000000: %d, 0x%X", numbertest, numbertest);
	numbertest = 0x7FFFFFFF;
	LOG_INF("NUMBERTEST 0x7FFFFFFF: %d, 0x%X", numbertest, numbertest);
	LOG_INF("END NUMBERTEST");

    /* USER BEGIN MAIN.C*/
    while(1){

		/* Extract the gPTP time NOW */
        status=gptp_event_capture(&slave_time, &gm_present);

		/* Make sure we are already received an external time reference */
		if (slave_time.second != 0) {
			/* Time can't go backwards. If we see this happen, it's clearly an error */
			if ((slave_time.second < prevsecond) || ((slave_time.second == prevsecond) && (slave_time.nanosecond < prevnanosecond)))
			{
				LOG_ERR("gptp time ERROR: TIME WENT BACKWARDS!!!!!%u.%u > %u.%u", prevsecond, prevnanosecond, slave_time.second, slave_time.nanosecond);
			}
			else {
				/* Make sure we are in our second loop and we have a previous reference */
				if ((prevsecond != 0) && (prevnanosecond != 0)) {
					/* Calculate how much time passed since the last sample */
					current_timelapse_ns = ((((slave_time.second - prevsecond) * 1000000000) + slave_time.nanosecond) - prevnanosecond);
					/* Calculate real lapse difference against the sleep time */
					lapse_diff_ns = current_timelapse_ns - (looptime_ms * 1000000);
					if (llabs(lapse_diff_ns) < abs(min_lapse_diff_ns))
					{
						/* Register the minimum value */
						/* Take care of value limits */
						if (lapse_diff_ns > 2147483648) {
							min_lapse_diff_ns = 2147483648;
						} else if (lapse_diff_ns < -2147483648) {
							min_lapse_diff_ns = -2147483648;
						} else {
							min_lapse_diff_ns = lapse_diff_ns;
						}
						LOG_WRN("gPTP time: New MIN lapse difference: %d", min_lapse_diff_ns);
					}
					if (llabs(lapse_diff_ns) > abs(max_lapse_diff_ns))
					{
						/* Register the minimum value */
						/* Take care of value limits */
						if (lapse_diff_ns > 2147483648) {
							max_lapse_diff_ns = 2147483648;
						} else if (lapse_diff_ns < -2147483648) {
							max_lapse_diff_ns = -2147483648;
						} else {
							max_lapse_diff_ns = lapse_diff_ns;
						}
						LOG_WRN("gPTP time: New MAX lapse difference: %d", max_lapse_diff_ns);
					}
					/* If the lapse difference is larger than the set limit, increase the error counter */
					if (abs(lapse_diff_ns) > lapse_diff_err_ns) {
						lapse_diff_err_count++;
					}
				}
			}

			/* Control report pacing */
			report_loop++;
			if (report_loop >= report_loops) {
				/* Print report */
				LOG_INF("gPTP time %u.%u", slave_time.second, slave_time.nanosecond);
				LOG_INF("gPTP lapse diff error count (%u ns): %u", lapse_diff_err_ns, lapse_diff_err_count);
				LOG_INF("gPTP max lapse difference: %d | gPTP min lapse difference: %d", max_lapse_diff_ns, min_lapse_diff_ns);
				report_loop = 0;
			}
		}
        prevsecond = slave_time.second;
        prevnanosecond = slave_time.nanosecond;
        k_msleep(looptime_ms); //sleep time in ms
    }
    /* USER END MAIN.C*/
}

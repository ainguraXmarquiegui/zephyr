/*
 * Copyright (c) 2020, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <init.h>
#include <fsl_iomuxc.h>
#include <fsl_gpio.h>

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
static gpio_pin_config_t enet_gpio_config = {
	.direction = kGPIO_DigitalOutput,
	.outputLogic = 0,
	.interruptMode = kGPIO_NoIntmode
};
#endif

static int mimxrt1024_evk_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	CLOCK_EnableClock(kCLOCK_Iomuxc);
	CLOCK_EnableClock(kCLOCK_IomuxcSnvs);

	/* LED */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_08_GPIO1_IO24, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_08_GPIO1_IO24,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	/* SW4 */
	IOMUXC_SetPinMux(IOMUXC_SNVS_WAKEUP_GPIO5_IO00, 0);

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpuart1), okay) && CONFIG_SERIAL
	/* LPUART1 TX/RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_06_LPUART1_TX, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_07_LPUART1_RX, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_06_LPUART1_TX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_07_LPUART1_RX,
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_04_GPIO1_IO04, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_06_GPIO1_IO22, 0U);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_10_ENET_RDATA00, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_09_ENET_RDATA01, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_11_ENET_RX_EN, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_14_ENET_TDATA00, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_15_ENET_TDATA01, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_13_ENET_TX_EN, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_08_ENET_REF_CLK1, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_12_ENET_RX_ER, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_41_ENET_MDC, 0);
	IOMUXC_SetPinMux(IOMUXC_GPIO_EMC_40_ENET_MDIO, 0);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_04_GPIO1_IO04, 0xB0A9u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_06_GPIO1_IO22, 0xB0A9u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_10_ENET_RDATA00, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_09_ENET_RDATA01, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_11_ENET_RX_EN, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_14_ENET_TDATA00, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_15_ENET_TDATA01, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_13_ENET_TX_EN, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_08_ENET_REF_CLK1, 0x31);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_12_ENET_RX_ER, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_41_ENET_MDC, 0xB0E9);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_EMC_40_ENET_MDIO, 0xB829);

	IOMUXC_EnableMode(IOMUXC_GPR, kIOMUXC_GPR_ENET1TxClkOutputDir, true);

	/* Initialize ENET_INT GPIO */
	GPIO_PinInit(GPIO1, 4, &enet_gpio_config);
	GPIO_PinInit(GPIO1, 22, &enet_gpio_config);

	/* pull up the ENET_INT before RESET. */
	GPIO_WritePinOutput(GPIO1, 22, 1);
	GPIO_WritePinOutput(GPIO1, 4, 0);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(flexcan1), okay) && CONFIG_CAN
	/* FlexCAN1 TX, RX */
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_00_FLEXCAN1_TX, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_01_FLEXCAN1_RX, 1);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_00_FLEXCAN1_TX, 0x10B0u);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_01_FLEXCAN1_RX, 0x10B0u);
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpi2c4), okay) && CONFIG_I2C
	/* LPI2C4 SCL, SDA - FXOS8700 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_02_LPI2C4_SCL, 1);
	IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B1_03_LPI2C4_SDA, 1);
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_02_LPI2C4_SCL,
			    IOMUXC_SW_PAD_CTL_PAD_PUS(3) |
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_ODE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B1_03_LPI2C4_SDA,
			    IOMUXC_SW_PAD_CTL_PAD_PUS(3) |
			    IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_ODE_MASK |
			    IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			    IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(lpspi1), okay) && CONFIG_SPI
#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
	#error "LPSPI1 and ENET share pins on this board, please disable one" \
			"using KConfig or the devicetree"
#else
	/* LPSPI1 CS, SDO, SDI, CLK exposed as pins 6, 8, 10, and 12 on J19 */
	/* GPIO_AD_B0_10 is configured as LPSPI1_SCK */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_10_LPSPI1_SCK, 0U);
	/* GPIO_AD_B0_11 is configured as LPSPI1_PCS0 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_11_LPSPI1_PCS0, 0U);
	/* GPIO_AD_B0_12 is configured as LPSPI1_SDO */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_12_LPSPI1_SDO, 0U);
	/* GPIO_AD_B0_13 is configured as LPSPI1_SDI */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_13_LPSPI1_SDI, 0U);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_10_LPSPI1_SCK,
			IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_11_LPSPI1_PCS0,
			IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_12_LPSPI1_SDO,
			IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_13_LPSPI1_SDI,
			IOMUXC_SW_PAD_CTL_PAD_PKE_MASK |
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
#endif
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(adc1), okay) && CONFIG_ADC
	/* ADC1 Channel 10 and 11 are on pins 2 and 4 of J18 */
	/* ADC1 Channel 10 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_10_GPIO1_IO26, 0U);
	/* ADC1 Channel 11 */
	IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B1_11_GPIO1_IO27, 0U);

	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_10_GPIO1_IO26,
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));
	IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B1_11_GPIO1_IO27,
			IOMUXC_SW_PAD_CTL_PAD_SPEED(2) |
			IOMUXC_SW_PAD_CTL_PAD_DSE(6));

#endif

	return 0;
}

#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
static int mimxrt1024_evk_phy_reset(const struct device *dev)
{
	/* RESET PHY chip. */
	k_busy_wait(USEC_PER_MSEC * 10U);
	GPIO_WritePinOutput(GPIO1, 4, 1);

	return 0;
}
#endif

SYS_INIT(mimxrt1024_evk_init, PRE_KERNEL_1, 0);
#if DT_NODE_HAS_STATUS(DT_NODELABEL(enet), okay) && CONFIG_NET_L2_ETHERNET
SYS_INIT(mimxrt1024_evk_phy_reset, POST_KERNEL, CONFIG_PHY_INIT_PRIORITY);
#endif

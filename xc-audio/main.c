/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 */

/*
 *  Xc_Audio soundcard
 *  Copyright (c) by Jaroslav Kysela <perex@perex.cz>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/init.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/tlv.h>
#include <sound/pcm.h>
#include <sound/rawmidi.h>
#include <sound/info.h>
#include <sound/initval.h>
#include "ring.h"

#define GRANT_INVALID_REF 0

#ifdef XC_HAS_STATIC_XEN

#include <xen/xenbus.h>
#if defined(CONFIG_XEN) || defined(MODULE)
#include <xen/evtchn.h>
#include <xen/interface/vcpu.h>
#include <asm/hypervisor.h>
#else
#include <asm/xen/hypervisor.h>
#include <xen/events.h>
#include <xen/page.h>
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
#include <linux/module.h>
#include <linux/export.h>
#include <xen/events.h>
#include <asm/xen/hypercall.h>
#include <xen/page.h>
#include <xen/evtchn.h>
#endif

#include <xen/grant_table.h>
#include <xen/interface/grant_table.h>

#define VCPUOP_get_time           14 /* arg == vcpu_get_time_t */
struct vcpu_get_time {
	uint64_t now;
};
typedef struct vcpu_get_time vcpu_get_time_t;
DEFINE_GUEST_HANDLE_STRUCT(vcpu_get_time_t);

uint64_t xc_xen_pv_get_time(void)
{
	int rc;
	struct vcpu_get_time t;
	t.now = 0UL;
	rc = HYPERVISOR_vcpu_op(VCPUOP_get_time, 0, &t);
	return t.now;
}

#else

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/interface/memory.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/ring.h>
#include "xen-time.h"

#endif

struct audfront_info {
	unsigned int evtchn;
	struct xenbus_device *xbdev;
	
	/* struct xen_aud_tx_front_ring tx; */
	int tx_ring_ref;
	int cmd_ring_ref;
	struct ring_t *cmd_ring;
	
	
	int irq;
	struct snd_xc_audio *xc_audio;

	struct snd_pcm_substream *playback_ss;
	struct be_info *playback_be_info;
	int playback_status;

	struct snd_pcm_substream *capture_ss;
	struct be_info *capture_be_info;
	int capture_status;

	uint32_t *shared_page;
};

struct audfront_info af_info;
uint32_t glob_playback_pointer = 0;
uint32_t glob_capture_pointer = 0;

uint64_t glob_playback_last_time = 0;
uint64_t glob_capture_last_time = 0;

MODULE_AUTHOR("Jaroslav Kysela <perex@perex.cz>");
MODULE_DESCRIPTION("Xc_Audio soundcard (/dev/null)");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("{{ALSA,Xc_Audio soundcard}}");

enum xc_stream {
	XC_STREAM_PLAYBACK = 0,
	XC_STREAM_CAPTURE,    
};

enum xc_cmd {
	XC_PCM_OPEN = 0,
	XC_PCM_CLOSE,
	XC_PCM_PREPARE,
	XC_TRIGGER_START,
	XC_TRIGGER_STOP,
};

enum stream_status {
	STREAM_STOPPED = 0,
	STREAM_STARTING,
	STREAM_STARTED,
	STREAM_STOPPING,
};

struct fe_cmd {
	uint8_t stream;
	uint8_t cmd;
	uint8_t data[6];
	uint64_t s_time;
} __attribute__((packed));

struct be_info {
	int hw_ptr;
	int delay;
	uint64_t total_processed; // not yet used
	uint64_t s_time;
	uint64_t appl_ptr;
	enum stream_status status;
};

#define N_AUD_BUFFER_PAGES 8

#define MAX_PCM_DEVICES		4
#define MAX_PCM_SUBSTREAMS	128
#define MAX_MIDI_DEVICES	2

/* defaults */
#define FIXED_PERIOD_FRAMES     (1024)
#define FIXED_PERIOD_SIZE       (1 * 4*FIXED_PERIOD_FRAMES)
#define FIXED_BUFFER_FRAMES     (N_AUD_BUFFER_PAGES * 1024)
#define MAX_BUFFER_SIZE		(N_AUD_BUFFER_PAGES * 4*1024)
#define MIN_PERIOD_SIZE		FIXED_PERIOD_SIZE
#define MAX_PERIOD_SIZE		FIXED_PERIOD_SIZE
#define USE_FORMATS 		(SNDRV_PCM_FMTBIT_U8 | SNDRV_PCM_FMTBIT_S16_LE)
#define USE_RATE		44100
#define USE_RATE_MIN		USE_RATE
#define USE_RATE_MAX		USE_RATE
#define USE_CHANNELS_MIN 	2
#define USE_CHANNELS_MAX 	2
#define USE_PERIODS_MIN 	(MAX_BUFFER_SIZE / FIXED_PERIOD_SIZE)
#define USE_PERIODS_MAX 	(MAX_BUFFER_SIZE / FIXED_PERIOD_SIZE)

static int index[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;	/* Index 0-MAX */
static char *id[SNDRV_CARDS] = SNDRV_DEFAULT_STR;	/* ID for this card */
static bool enable[SNDRV_CARDS] = {1, [1 ... (SNDRV_CARDS - 1)] = 0};
static int pcm_devs[SNDRV_CARDS] = {[0 ... (SNDRV_CARDS - 1)] = 1};
static int pcm_substreams[SNDRV_CARDS] = {[0 ... (SNDRV_CARDS - 1)] = 1};

module_param_array(index, int, NULL, 0444);
MODULE_PARM_DESC(index, "Index value for xc_audio soundcard.");
module_param_array(id, charp, NULL, 0444);
MODULE_PARM_DESC(id, "ID string for xc_audio soundcard.");
module_param_array(enable, bool, NULL, 0444);
MODULE_PARM_DESC(enable, "Enable this xc_audio soundcard.");
module_param_array(pcm_devs, int, NULL, 0444);
MODULE_PARM_DESC(pcm_devs, "PCM devices # (0-4) for xc_audio driver.");
module_param_array(pcm_substreams, int, NULL, 0444);
MODULE_PARM_DESC(pcm_substreams, "PCM substreams # (1-128) for xc_audio driver.");

static struct platform_device *devices[SNDRV_CARDS];

#define MIXER_ADDR_MASTER	0
#define MIXER_ADDR_LINE		1
#define MIXER_ADDR_MIC		2
#define MIXER_ADDR_SYNTH	3
#define MIXER_ADDR_CD		4
#define MIXER_ADDR_LAST		4


struct snd_xc_audio {
	struct snd_card *card;
	struct snd_pcm *pcm;
	struct snd_pcm_hardware pcm_hw;
	spinlock_t mixer_lock;
	int mixer_volume[MIXER_ADDR_LAST+1][2];
	int capture_source[MIXER_ADDR_LAST+1][2];       
};

static DEFINE_MUTEX(xenaudio_pm_mutex);

void send_fe_cmd(enum xc_stream stream, 
		 enum xc_cmd cmd, 
		 uint8_t *data,
		 uint64_t s_time)
{
	struct fe_cmd fe_cmd;
	int i;

	fe_cmd.stream = stream;
	fe_cmd.cmd = cmd;
	if (data != NULL) {
		for (i = 0; i < 6; i++) {
			fe_cmd.data[i] = data[i];
		}
	}
	fe_cmd.s_time = s_time;

	ring_write(af_info.cmd_ring, &fe_cmd, sizeof(fe_cmd));
	notify_remote_via_irq(af_info.irq);
}

#ifdef USE_CROSS_DOMAIN_TIME_DIFF
static snd_pcm_uframes_t
dummy_hrtimer_pointer2(struct snd_pcm_substream *substream, uint64_t s_time)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	uint64_t delta, delta_nsec, curr_time;
	u32 pos;

#ifdef XC_HAS_STATIC_XEN
	curr_time = xc_xen_pv_get_time();
#else
	curr_time = xc_xen_get_time();
#endif
	delta_nsec = curr_time - s_time;
	delta = div_u64(delta_nsec, 1000);
	delta = div_u64(delta * runtime->rate + 999999, 1000000);
	div_u64_rem(delta, runtime->buffer_size, &pos);
	//printk(KERN_ERR "curr_time=%llu s_time=%llu pos=%d\n", curr_time, s_time, pos);
	return pos;
}
#endif /* USE_CROSS_DOMAIN_TIME_DIFF */

/*
 * PCM interface
 */

static int xc_audio_pcm_trigger(struct snd_pcm_substream *substream, int cmd)
{
	uint64_t time_nsec = 0;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		printk(KERN_ERR "SSSS %s:%d START period=%d buffer_size=%d substr=%p\n", __FUNCTION__, __LINE__,
		       (int)substream->runtime->period_size, (int)substream->runtime->buffer_size, substream);
		break;
	case SNDRV_PCM_TRIGGER_RESUME:
		printk(KERN_ERR "SSSS %s:%d RESUME period=%d buffer_size=%d substr=%p\n", __FUNCTION__, __LINE__,
		       (int)substream->runtime->period_size, (int)substream->runtime->buffer_size, substream);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		printk(KERN_ERR "SSSS %s:%d STOP period=%d buffer_size=%d substr=%p\n", __FUNCTION__, __LINE__,
		       (int)substream->runtime->period_size, (int)substream->runtime->buffer_size, substream);
		break;
	case SNDRV_PCM_TRIGGER_SUSPEND:
		printk(KERN_ERR "SSSS %s:%d SUSPEND period=%d buffer_size=%d substr=%p\n", __FUNCTION__, __LINE__,
		       (int)substream->runtime->period_size, (int)substream->runtime->buffer_size, substream);
		break;
	}

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
#ifdef XC_HAS_STATIC_XEN
		time_nsec = xc_xen_pv_get_time();
#else
		time_nsec = xc_xen_get_time();
#endif
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			glob_playback_last_time = time_nsec;
			af_info.playback_ss = substream;
			af_info.playback_status = STREAM_STARTING;
			send_fe_cmd(XC_STREAM_PLAYBACK, XC_TRIGGER_START, NULL, time_nsec);
		} else {
			glob_capture_last_time = time_nsec;
			af_info.capture_ss = substream;
			af_info.capture_status = STREAM_STARTING;
			send_fe_cmd(XC_STREAM_CAPTURE, XC_TRIGGER_START, NULL, time_nsec);
		}
		return 0;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			af_info.playback_status = STREAM_STOPPING;
			send_fe_cmd(XC_STREAM_PLAYBACK, XC_TRIGGER_STOP, NULL, time_nsec);
			af_info.playback_ss = NULL;
		} else {
			af_info.capture_status = STREAM_STOPPING;
			send_fe_cmd(XC_STREAM_CAPTURE, XC_TRIGGER_STOP, NULL, time_nsec);
			af_info.capture_ss = NULL;
		}
		return 0;
	}

	return -EINVAL;
}

static int xc_audio_pcm_prepare(struct snd_pcm_substream *substream)
{
	printk(KERN_ERR "%s:%d substr=%p\n", __FUNCTION__, __LINE__, substream);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		glob_playback_pointer = 0;
		send_fe_cmd(XC_STREAM_PLAYBACK, XC_PCM_PREPARE, NULL, 0);
	} else {
		glob_capture_pointer = 0;
		send_fe_cmd(XC_STREAM_CAPTURE, XC_PCM_PREPARE, NULL, 0);
	}
	return 0;
}


static snd_pcm_uframes_t xc_audio_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct be_info *be_info;
	uint32_t pointer = 0;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		if (af_info.playback_ss != NULL) {
			be_info = af_info.playback_be_info;
			//delay = be_info->delay - dummy_hrtimer_pointer2(substream, be_info->s_time);
			be_info->appl_ptr = substream->runtime->control->appl_ptr;
			wmb();
			rmb();
			pointer = be_info->hw_ptr;
		} else {
			pointer = glob_playback_pointer;
		}
		//substream->runtime->delay = delay;
		
		/* printk(KERN_ERR "SSSS %s:%d PLAYBACK pointer=%d r->delay=%d\n", __FUNCTION__, __LINE__, */
		/* 	 glob_playback_pointer, substream->runtime->delay); */
	} else {
		if (af_info.capture_ss != NULL) {
			be_info = af_info.capture_be_info;
			//delay = be_info->delay + dummy_hrtimer_pointer2(substream, be_info->s_time);
			be_info->appl_ptr = substream->runtime->control->appl_ptr;
			wmb();
			rmb();
			pointer = be_info->hw_ptr;
		} else {
			pointer = glob_capture_pointer;
		}
		//substream->runtime->delay = delay;
		
		/* printk(KERN_ERR "SSSS %s:%d CAPTURE pointer=%d r->delay=%d\n", __FUNCTION__, __LINE__, */
		/* 	 glob_capture_pointer, substream->runtime->delay); */
	}
	return pointer;
}

static struct snd_pcm_hardware xc_audio_pcm_hardware = {
	.info =			(SNDRV_PCM_INFO_MMAP |
				 SNDRV_PCM_INFO_INTERLEAVED |
				 SNDRV_PCM_INFO_MMAP_VALID |
				 SNDRV_PCM_INFO_BLOCK_TRANSFER |
				 SNDRV_PCM_INFO_FIFO_IN_FRAMES),
	.formats =		USE_FORMATS,
	.rates =		USE_RATE,
	.rate_min =		USE_RATE_MIN,
	.rate_max =		USE_RATE_MAX,
	.channels_min =		USE_CHANNELS_MIN,
	.channels_max =		USE_CHANNELS_MAX,
	.buffer_bytes_max =	MAX_BUFFER_SIZE,
	.period_bytes_min =	MIN_PERIOD_SIZE,
	.period_bytes_max =	MAX_PERIOD_SIZE,
	.periods_min =		USE_PERIODS_MIN,
	.periods_max =		USE_PERIODS_MAX,
	.fifo_size =		4096,
};

static int xc_audio_pcm_hw_params(struct snd_pcm_substream *substream,
				  struct snd_pcm_hw_params *hw_params)
{
	substream->runtime->dma_bytes = params_buffer_bytes(hw_params);
	return 0;
}

static int xc_audio_pcm_hw_free(struct snd_pcm_substream *substream)
{
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);
	return 0;
}

static int xc_audio_pcm_open(struct snd_pcm_substream *substream)
{
	struct snd_xc_audio *xc_audio = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		af_info.playback_ss = substream;
		glob_playback_pointer = 0;
		af_info.playback_status = STREAM_STOPPED;
	} else {
		af_info.capture_ss = substream;
		glob_capture_pointer = 0;
		af_info.capture_status = STREAM_STOPPED;
	}
	
	runtime->hw = xc_audio->pcm_hw;
	if (substream->pcm->device & 1) {
		runtime->hw.info &= ~SNDRV_PCM_INFO_INTERLEAVED;
		runtime->hw.info |= SNDRV_PCM_INFO_NONINTERLEAVED;
	}
	if (substream->pcm->device & 2)
		runtime->hw.info &= ~(SNDRV_PCM_INFO_MMAP |
				      SNDRV_PCM_INFO_MMAP_VALID);
	
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		send_fe_cmd(XC_STREAM_PLAYBACK, XC_PCM_OPEN, NULL, 0);
	} else {
		send_fe_cmd(XC_STREAM_CAPTURE, XC_PCM_OPEN, NULL, 0);
	}
	return 0;
}

static int xc_audio_pcm_close(struct snd_pcm_substream *substream)
{
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		af_info.playback_ss = NULL;
	} else {
		af_info.capture_ss = NULL;
	}
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		send_fe_cmd(XC_STREAM_PLAYBACK, XC_PCM_CLOSE, NULL, 0);
	} else {
		send_fe_cmd(XC_STREAM_CAPTURE, XC_PCM_CLOSE, NULL, 0);
	}
	return 0;
}

/*
 * xc_audio buffer handling
 */


static void *xc_playback_page[N_AUD_BUFFER_PAGES];
static void *xc_capture_page[N_AUD_BUFFER_PAGES];

static int page_gref = 0;
static int playback_grefs[N_AUD_BUFFER_PAGES];
static int capture_grefs[N_AUD_BUFFER_PAGES];

static int xc_audio_pcm_copy(struct snd_pcm_substream *substream,
			     int channel, snd_pcm_uframes_t pos,
			     void __user *dst, snd_pcm_uframes_t count)
{
	int page_index, page_pos;
	/* printk(KERN_ERR "%s: %c: pos=%d, dst=%p, count=%d\n", */
	/*        __FUNCTION__, (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ? 'P' : 'C', pos, dst, count); */

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		while (count) {
			page_index=pos/1024;
			page_pos=pos%1024;
			if ((count >= 1024) && (page_pos == 0)) {
				memcpy(xc_playback_page[page_index], dst, 4096);
				dst += 4096;
				pos += 1024;
				count -= 1024;
			} else {
				*(uint32_t *)(xc_playback_page[page_index] + page_pos*4) = *(uint32_t *)dst;
				dst += 4;
				pos++;
				count--;
			}
		}
	} else {
		while (count) {
			page_index=pos/1024;
			page_pos=pos%1024;

			if ((count >= 1024) && (page_pos == 0)) {
				memcpy(dst, xc_capture_page[page_index], 4096);
				dst += 4096;
				pos += 1024;
				count -= 1024;
			} else {
				*(uint32_t *)dst = *(uint32_t *)(xc_capture_page[page_index] + page_pos*4);
				dst += 4;
				pos++;
				count--;
			}
		}
	}
	return 0; /* do nothing */
}

static int xc_audio_pcm_silence(struct snd_pcm_substream *substream,
				int channel, snd_pcm_uframes_t pos,
				snd_pcm_uframes_t count)
{
	/* printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__); */
	return 0; /* do nothing */
}

static struct page *xc_audio_pcm_page(struct snd_pcm_substream *substream,
				      unsigned long offset)
{
	int page_index = offset/4096;
	printk(KERN_ERR "SSSS xc_audio_pcm_page offset=%lu, page_index=%d\n", offset, page_index);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return virt_to_page(xc_playback_page[page_index]); /* the same page */
	else 
		return virt_to_page(xc_capture_page[page_index]);
}

static struct snd_pcm_ops xc_audio_pcm_ops_no_buf = {
	.open =		xc_audio_pcm_open,
	.close =	xc_audio_pcm_close,
	.ioctl =	snd_pcm_lib_ioctl,
	.hw_params =	xc_audio_pcm_hw_params,
	.hw_free =	xc_audio_pcm_hw_free,
	.prepare =	xc_audio_pcm_prepare,
	.trigger =	xc_audio_pcm_trigger,
	.pointer =	xc_audio_pcm_pointer,
	.copy =		xc_audio_pcm_copy,
	.silence =	xc_audio_pcm_silence,
	.page =		xc_audio_pcm_page,
};

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int snd_card_xc_audio_pcm(struct snd_xc_audio *xc_audio, int device, int substreams)
#else
static int __devinit snd_card_xc_audio_pcm(struct snd_xc_audio *xc_audio, int device, int substreams)
#endif
{
	struct snd_pcm *pcm;
	struct snd_pcm_ops *ops;
	int err;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	err = snd_pcm_new(xc_audio->card, "Xc_Audio PCM", device,
			  substreams, substreams, &pcm);
	if (err < 0)
		return err;
	xc_audio->pcm = pcm;
	ops = &xc_audio_pcm_ops_no_buf;
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, ops);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, ops);
	pcm->private_data = xc_audio;
	pcm->info_flags = 0;
	strcpy(pcm->name, "Xc_Audio PCM");
	return 0;
}

/*
 * mixer interface
 */

#if 0
#define XC_AUDIO_VOLUME(xname, xindex, addr)				\
	{ .iface = SNDRV_CTL_ELEM_IFACE_MIXER,				\
			.access = SNDRV_CTL_ELEM_ACCESS_READWRITE | SNDRV_CTL_ELEM_ACCESS_TLV_READ, \
			.name = xname, .index = xindex,			\
			.info = snd_xc_audio_volume_info,		\
			.get = snd_xc_audio_volume_get, .put = snd_xc_audio_volume_put, \
			.private_value = addr,				\
			.tlv = { .p = db_scale_xc_audio } }

static int snd_xc_audio_volume_info(struct snd_kcontrol *kcontrol,
				    struct snd_ctl_elem_info *uinfo)
{
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 2;
	uinfo->value.integer.min = -50;
	uinfo->value.integer.max = 100;
	return 0;
}
 
static int snd_xc_audio_volume_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct snd_xc_audio *xc_audio = snd_kcontrol_chip(kcontrol);
	int addr = kcontrol->private_value;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	spin_lock_irq(&xc_audio->mixer_lock);
	ucontrol->value.integer.value[0] = xc_audio->mixer_volume[addr][0];
	ucontrol->value.integer.value[1] = xc_audio->mixer_volume[addr][1];
	spin_unlock_irq(&xc_audio->mixer_lock);
	return 0;
}

static int snd_xc_audio_volume_put(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	// uint32_t *hp = af_info.shared_page;
	struct snd_xc_audio *xc_audio = snd_kcontrol_chip(kcontrol);
	int change, addr = kcontrol->private_value;
	int left, right;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	left = ucontrol->value.integer.value[0];
	if (left < -50)
		left = -50;
	if (left > 100)
		left = 100;
	right = ucontrol->value.integer.value[1];
	if (right < -50)
		right = -50;
	if (right > 100)
		right = 100;
	spin_lock_irq(&xc_audio->mixer_lock);
	change = xc_audio->mixer_volume[addr][0] != left ||
		xc_audio->mixer_volume[addr][1] != right;
	xc_audio->mixer_volume[addr][0] = left;
	xc_audio->mixer_volume[addr][1] = right;
	printk(KERN_ERR "addr=%d left=%d right=%d\n", addr, left, right);

	/* if (addr == 0) { */
	/*   hp[XC_AUD_LEFT_VOL_P] = left; */
	/*   hp[XC_AUD_RIGHT_VOL_P] = right; */
	/* } else if (addr == 1) { */
	/*   hp[XC_AUD_LEFT_VOL_C] = left; */
	/*   hp[XC_AUD_RIGHT_VOL_C] = right; */
	/* } */

	spin_unlock_irq(&xc_audio->mixer_lock);
	return change;
}
#endif

static const DECLARE_TLV_DB_SCALE(db_scale_xc_audio, -4500, 30, 0);

#define XC_AUDIO_CAPSRC(xname, xindex, addr)				\
	{ .iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, .index = xindex, \
			.info = snd_xc_audio_capsrc_info,		\
			.get = snd_xc_audio_capsrc_get, .put = snd_xc_audio_capsrc_put, \
			.private_value = addr }

#define snd_xc_audio_capsrc_info	snd_ctl_boolean_stereo_info

#if 0
static int snd_xc_audio_capsrc_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct snd_xc_audio *xc_audio = snd_kcontrol_chip(kcontrol);
	int addr = kcontrol->private_value;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	spin_lock_irq(&xc_audio->mixer_lock);
	ucontrol->value.integer.value[0] = xc_audio->capture_source[addr][0];
	ucontrol->value.integer.value[1] = xc_audio->capture_source[addr][1];
	spin_unlock_irq(&xc_audio->mixer_lock);
	return 0;
}

static int snd_xc_audio_capsrc_put(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol)
{
	struct snd_xc_audio *xc_audio = snd_kcontrol_chip(kcontrol);
	int change, addr = kcontrol->private_value;
	int left, right;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	left = ucontrol->value.integer.value[0] & 1;
	right = ucontrol->value.integer.value[1] & 1;
	spin_lock_irq(&xc_audio->mixer_lock);
	change = xc_audio->capture_source[addr][0] != left &&
		xc_audio->capture_source[addr][1] != right;
	xc_audio->capture_source[addr][0] = left;
	xc_audio->capture_source[addr][1] = right;
	spin_unlock_irq(&xc_audio->mixer_lock);
	return change;
}

#endif

static struct snd_kcontrol_new snd_xc_audio_controls[] = {
/* XC_AUDIO_VOLUME("Master Volume", 0, MIXER_ADDR_MASTER), */
/* XC_AUDIO_CAPSRC("Master Capture Switch", 0, MIXER_ADDR_MASTER), */
/* XC_AUDIO_VOLUME("Synth Volume", 0, MIXER_ADDR_SYNTH), */
/* XC_AUDIO_CAPSRC("Synth Capture Switch", 0, MIXER_ADDR_SYNTH), */
/* XC_AUDIO_VOLUME("Line Volume", 0, MIXER_ADDR_LINE), */
/* XC_AUDIO_CAPSRC("Line Capture Switch", 0, MIXER_ADDR_LINE), */
/* XC_AUDIO_VOLUME("Mic Volume", 0, MIXER_ADDR_MIC), */
/* XC_AUDIO_CAPSRC("Mic Capture Switch", 0, MIXER_ADDR_MIC), */
/* XC_AUDIO_VOLUME("CD Volume", 0, MIXER_ADDR_CD), */
/* XC_AUDIO_CAPSRC("CD Capture Switch", 0, MIXER_ADDR_CD) */
};

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int snd_card_xc_audio_new_mixer(struct snd_xc_audio *xc_audio)
#else
static int __devinit snd_card_xc_audio_new_mixer(struct snd_xc_audio *xc_audio)
#endif
{
	struct snd_card *card = xc_audio->card;
	unsigned int idx;
	int err;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	spin_lock_init(&xc_audio->mixer_lock);
	strcpy(card->mixername, "Xc_Audio Mixer");

	for (idx = 0; idx < ARRAY_SIZE(snd_xc_audio_controls); idx++) {
		err = snd_ctl_add(card, snd_ctl_new1(&snd_xc_audio_controls[idx], xc_audio));
		if (err < 0)
			return err;
	}
	return 0;
}

#if defined(CONFIG_SND_DEBUG) && defined(CONFIG_PROC_FS)
/*
 * proc interface
 */
static void print_formats(struct snd_xc_audio *xc_audio,
			  struct snd_info_buffer *buffer)
{
	int i;
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	for (i = 0; i < SNDRV_PCM_FORMAT_LAST; i++) {
		if (xc_audio->pcm_hw.formats & (1ULL << i))
			snd_iprintf(buffer, " %s", snd_pcm_format_name(i));
	}
}

static void print_rates(struct snd_xc_audio *xc_audio,
			struct snd_info_buffer *buffer)
{
	static int rates[] = {USE_RATE};
	int i;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	if (xc_audio->pcm_hw.rates & SNDRV_PCM_RATE_CONTINUOUS)
		snd_iprintf(buffer, " continuous");
	if (xc_audio->pcm_hw.rates & SNDRV_PCM_RATE_KNOT)
		snd_iprintf(buffer, " knot");
	for (i = 0; i < ARRAY_SIZE(rates); i++)
		if (xc_audio->pcm_hw.rates & (1 << i))
			snd_iprintf(buffer, " %d", rates[i]);
}

#define get_xc_audio_int_ptr(xc_audio, ofs)			\
	(unsigned int *)((char *)&((xc_audio)->pcm_hw) + (ofs))
#define get_xc_audio_ll_ptr(xc_audio, ofs)				\
	(unsigned long long *)((char *)&((xc_audio)->pcm_hw) + (ofs))

struct xc_audio_hw_field {
	const char *name;
	const char *format;
	unsigned int offset;
	unsigned int size;
};
#define FIELD_ENTRY(item, fmt) {					\
		.name = #item,						\
			.format = fmt,					\
			.offset = offsetof(struct snd_pcm_hardware, item), \
			.size = sizeof(xc_audio_pcm_hardware.item) }

static struct xc_audio_hw_field fields[] = {
	FIELD_ENTRY(formats, "%#llx"),
	FIELD_ENTRY(rates, "%#x"),
	FIELD_ENTRY(rate_min, "%d"),
	FIELD_ENTRY(rate_max, "%d"),
	FIELD_ENTRY(channels_min, "%d"),
	FIELD_ENTRY(channels_max, "%d"),
	FIELD_ENTRY(buffer_bytes_max, "%ld"),
	FIELD_ENTRY(period_bytes_min, "%ld"),
	FIELD_ENTRY(period_bytes_max, "%ld"),
	FIELD_ENTRY(periods_min, "%d"),
	FIELD_ENTRY(periods_max, "%d"),
};

static void xc_audio_proc_read(struct snd_info_entry *entry,
			       struct snd_info_buffer *buffer)
{
	struct snd_xc_audio *xc_audio = entry->private_data;
	int i;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		snd_iprintf(buffer, "%s ", fields[i].name);
		if (fields[i].size == sizeof(int))
			snd_iprintf(buffer, fields[i].format,
				    *get_xc_audio_int_ptr(xc_audio, fields[i].offset));
		else
			snd_iprintf(buffer, fields[i].format,
				    *get_xc_audio_ll_ptr(xc_audio, fields[i].offset));
		if (!strcmp(fields[i].name, "formats"))
			print_formats(xc_audio, buffer);
		else if (!strcmp(fields[i].name, "rates"))
			print_rates(xc_audio, buffer);
		snd_iprintf(buffer, "\n");
	}
}

static void xc_audio_proc_write(struct snd_info_entry *entry,
				struct snd_info_buffer *buffer)
{
	struct snd_xc_audio *xc_audio = entry->private_data;
	char line[64];

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	while (!snd_info_get_line(buffer, line, sizeof(line))) {
		char item[20];
		const char *ptr;
		unsigned long long val;
		int i;

		ptr = snd_info_get_str(item, line, sizeof(item));
		for (i = 0; i < ARRAY_SIZE(fields); i++) {
			if (!strcmp(item, fields[i].name))
				break;
		}
		if (i >= ARRAY_SIZE(fields))
			continue;
		snd_info_get_str(item, ptr, sizeof(item));
		if (strict_strtoull(item, 0, &val))
			continue;
		if (fields[i].size == sizeof(int))
			*get_xc_audio_int_ptr(xc_audio, fields[i].offset) = val;
		else
			*get_xc_audio_ll_ptr(xc_audio, fields[i].offset) = val;
	}
}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static void xc_audio_proc_init(struct snd_xc_audio *chip)
#else
static void __devinit xc_audio_proc_init(struct snd_xc_audio *chip)
#endif
{
	struct snd_info_entry *entry;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	if (!snd_card_proc_new(chip->card, "xc_audio_pcm", &entry)) {
		snd_info_set_text_ops(entry, chip, xc_audio_proc_read);
		entry->c.text.write = xc_audio_proc_write;
		entry->mode |= S_IWUSR;
		entry->private_data = chip;
	}
}
#else
#define xc_audio_proc_init(x)
#endif /* CONFIG_SND_DEBUG && CONFIG_PROC_FS */

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int snd_xc_audio_probe(struct platform_device *devptr)
#else
static int __devinit snd_xc_audio_probe(struct platform_device *devptr)
#endif
{
	struct snd_card *card;
	struct snd_xc_audio *xc_audio;
	int idx, err;
	int dev = devptr->id;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	err = snd_card_create(index[dev], id[dev], THIS_MODULE,
			      sizeof(struct snd_xc_audio), &card);
	if (err < 0)
		return err;
	xc_audio = card->private_data;
	xc_audio->card = card;
	af_info.xc_audio = xc_audio;
	af_info.playback_ss = NULL;
	af_info.capture_ss = NULL;

	for (idx = 0; idx < MAX_PCM_DEVICES && idx < pcm_devs[dev]; idx++) {
		if (pcm_substreams[dev] < 1)
			pcm_substreams[dev] = 1;
		if (pcm_substreams[dev] > MAX_PCM_SUBSTREAMS)
			pcm_substreams[dev] = MAX_PCM_SUBSTREAMS;
		err = snd_card_xc_audio_pcm(xc_audio, idx, pcm_substreams[dev]);
		if (err < 0)
			goto __nodev;
	}

	xc_audio->pcm_hw = xc_audio_pcm_hardware;

	err = snd_card_xc_audio_new_mixer(xc_audio);
	if (err < 0)
		goto __nodev;
	strcpy(card->driver, "Xc_Audio");
	strcpy(card->shortname, "Xc_Audio");
	sprintf(card->longname, "Xc_Audio %i", dev + 1);

	xc_audio_proc_init(xc_audio);

	snd_card_set_dev(card, &devptr->dev);

	err = snd_card_register(card);
	if (err == 0) {
		platform_set_drvdata(devptr, card);
		return 0;
	}
__nodev:
	snd_card_free(card);
	return err;
}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int snd_xc_audio_remove(struct platform_device *devptr)
#else
static int __devexit snd_xc_audio_remove(struct platform_device *devptr)
#endif
{
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);
	snd_card_free(platform_get_drvdata(devptr));
	platform_set_drvdata(devptr, NULL);
	return 0;
}

#ifdef CONFIG_PM
static int snd_xc_audio_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct snd_card *card = platform_get_drvdata(pdev);
	struct snd_xc_audio *xc_audio = card->private_data;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	snd_power_change_state(card, SNDRV_CTL_POWER_D3hot);
	snd_pcm_suspend_all(xc_audio->pcm);
	return 0;
}
	
static int snd_xc_audio_resume(struct platform_device *pdev)
{
	struct snd_card *card = platform_get_drvdata(pdev);

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	snd_power_change_state(card, SNDRV_CTL_POWER_D0);
	return 0;
}
#endif

#define SND_XC_AUDIO_DRIVER	"snd_xc_audio"

static struct platform_driver snd_xc_audio_driver = {
	.probe		= snd_xc_audio_probe,
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
	.remove		= snd_xc_audio_remove,
#else
	.remove		= __devexit_p(snd_xc_audio_remove),
#endif
#ifdef CONFIG_PM
	.suspend	= snd_xc_audio_suspend,
	.resume		= snd_xc_audio_resume,
#endif
	.driver		= {
		.name	= SND_XC_AUDIO_DRIVER,
		.owner  = THIS_MODULE
	},
};

static void snd_xc_audio_unregister_all(void)
{
	int i;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	for (i = 0; i < ARRAY_SIZE(devices); ++i)
		platform_device_unregister(devices[i]);
	platform_driver_unregister(&snd_xc_audio_driver);
}

static int alsa_card_xc_audio_init(void)
{
	int i, cards, err;

	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);

	err = platform_driver_register(&snd_xc_audio_driver);
	if (err < 0)
		return err;

	if (err < 0) {
		platform_driver_unregister(&snd_xc_audio_driver);
		return err;
	}

	cards = 0;
	for (i = 0; i < SNDRV_CARDS; i++) {
		struct platform_device *device;
		if (! enable[i])
			continue;
		device = platform_device_register_simple(SND_XC_AUDIO_DRIVER,
							 i, NULL, 0);
		if (IS_ERR(device))
			continue;
		if (!platform_get_drvdata(device)) {
			platform_device_unregister(device);
			continue;
		}
		devices[i] = device;
		cards++;
	}
	if (!cards) {
		printk(KERN_ERR "Xc_Audio soundcard not found or device busy\n");
		snd_xc_audio_unregister_all();
		return -ENODEV;
	}
	return 0;
}

static void alsa_card_xc_audio_exit(void)
{
	printk(KERN_ERR "%s:%d\n", __FUNCTION__, __LINE__);
	snd_xc_audio_unregister_all();
}


static struct xenbus_device_id audfront_ids[] = {
	{ "vsnd" },
	{ "" }
};

/**
 * We are reconnecting to the backend, due to a suspend/resume, or a backend
 * driver restart.
 */
static int audfront_resume(struct xenbus_device *dev)
{
	printk(KERN_ERR "%s\n", dev->nodename);
	return 0;
}

static irqreturn_t xenaud_interrupt(int irq, void *dev_id)
{
	struct snd_pcm_substream *substream;
	struct be_info *be_info;
	int frames_done;
	uint32_t new_pointer;
	uint64_t time_diff, time_nsec;

	rmb();
#ifdef XC_HAS_STATIC_XEN
	time_nsec = xc_xen_pv_get_time();
#else
	time_nsec = xc_xen_get_time();
#endif
	//printk(KERN_ERR "Int received\n");

	be_info = af_info.playback_be_info;
	
	if (af_info.playback_status == STREAM_STARTED) {
		substream = af_info.playback_ss;

		time_diff = time_nsec - glob_playback_last_time;
		if (time_diff > 60000000)
			printk(KERN_ERR "P time_diff=%llu\n", div_u64(time_diff, 1000000));
		glob_playback_last_time = time_nsec;

		new_pointer = be_info->hw_ptr;
		frames_done = new_pointer - glob_playback_pointer;
		if (frames_done < 0) {
			frames_done = FIXED_BUFFER_FRAMES + frames_done;
		}

		if (frames_done >= FIXED_PERIOD_FRAMES ) {
			snd_pcm_period_elapsed(af_info.playback_ss);
			glob_playback_pointer = new_pointer;
			//printk(KERN_ERR "P period elapsed\n");
		}
	}
	if (af_info.playback_status == STREAM_STOPPING) {
		if (be_info->status == STREAM_STOPPED)
			af_info.playback_status = STREAM_STOPPED;
	}
	if (af_info.playback_status == STREAM_STARTING) {
		if (be_info->status == STREAM_STARTING)
			af_info.playback_status = STREAM_STARTED;
	}

	be_info = af_info.capture_be_info;
	if (af_info.capture_status == STREAM_STARTED) {
		substream = af_info.capture_ss;
		
		time_diff = time_nsec - glob_capture_last_time;
		if (time_diff > 60000000)
			printk(KERN_ERR "C time_diff=%llu\n", div_u64(time_diff, 1000000));
		glob_capture_last_time = time_nsec;

		new_pointer = be_info->hw_ptr;
		frames_done = new_pointer - glob_capture_pointer;
		if (frames_done < 0) {
			frames_done = FIXED_BUFFER_FRAMES + frames_done;
		}

		if (frames_done >= FIXED_PERIOD_FRAMES ) {
			snd_pcm_period_elapsed(af_info.capture_ss);
			glob_capture_pointer = new_pointer;
			//printk(KERN_ERR "C period elapsed\n");
		}
	}
	if (af_info.capture_status == STREAM_STOPPING) {
		if (be_info->status == STREAM_STOPPED)
			af_info.capture_status = STREAM_STOPPED;
	}
	if (af_info.capture_status == STREAM_STARTING) {
		if (be_info->status == STREAM_STARTING)
			af_info.capture_status = STREAM_STARTED;
	}
	

	return IRQ_HANDLED;
}

static int setup_audfront(struct xenbus_device *dev, struct audfront_info *info)
{
	void *txs;
	int err, i;
	uint32_t *page_ref;

	printk(KERN_ERR "setup_audfront %s \n", __FUNCTION__);
	info->tx_ring_ref = 0;

	txs = (void *)get_zeroed_page(GFP_KERNEL);
	if (!txs) {
		err = -ENOMEM;
		xenbus_dev_fatal(dev, err, "allocating tx ring page");
		goto fail;
	}
	af_info.shared_page = page_ref = txs;
	err = xenbus_grant_ring(dev, virt_to_mfn(txs));
	if (err < 0) {
		free_page((unsigned long)txs);
		goto fail;
	}

	page_gref = err;
	info->tx_ring_ref = virt_to_mfn(txs);

	/* playback pages */
	for (i=0; i<N_AUD_BUFFER_PAGES; i++) {
		xc_playback_page[i] = (void *)get_zeroed_page(GFP_KERNEL);
		if (!xc_playback_page[i]) {
			err = -ENOMEM;
			xenbus_dev_fatal(dev, err, "allocating tx ring page");
			goto fail;
		}
		err = xenbus_grant_ring(dev, virt_to_mfn(xc_playback_page[i]));
		if (err < 0) {
			free_page((unsigned long)xc_playback_page[i]);
			goto fail;
		}
		playback_grefs[i] = err;
		page_ref[100 + i] = virt_to_mfn(xc_playback_page[i]);
	  
	}

	/* capture pages */
	for (i=0; i<N_AUD_BUFFER_PAGES; i++) {
		xc_capture_page[i] = (void *)get_zeroed_page(GFP_KERNEL);
		if (!xc_capture_page[i]) {
			err = -ENOMEM;
			xenbus_dev_fatal(dev, err, "allocating tx ring page");
			goto fail;
		}
		err = xenbus_grant_ring(dev, virt_to_mfn(xc_capture_page[i]));
		if (err < 0) {
			free_page((unsigned long)xc_capture_page[i]);
			goto fail;
		}
		capture_grefs[i] = err;
		page_ref[200 + i] = virt_to_mfn(xc_capture_page[i]);
	  
	}

	/* commands ring */
	info->cmd_ring = (struct ring_t *) get_zeroed_page(GFP_KERNEL);
	if (!info->cmd_ring) {
		err = -ENOMEM;
		xenbus_dev_fatal(dev, err, "allocating commands ring page");
		goto fail;
	}
	ring_init(info->cmd_ring);

	err = xenbus_grant_ring(dev, virt_to_mfn(info->cmd_ring));
	if (err < 0) {
		free_page((unsigned long)info->cmd_ring);
		goto fail;
	}
	info->cmd_ring_ref = err;
	page_ref[300] = virt_to_mfn(info->cmd_ring);

	info->playback_be_info = (struct be_info *)&page_ref[400];
	info->capture_be_info = (struct be_info *)&page_ref[500];

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err)
		goto fail;
#if defined(XC_HAS_STATIC_XEN) && ( LINUX_VERSION_CODE <= KERNEL_VERSION(3,7,0) )
	err = bind_caller_port_to_irqhandler(info->evtchn, xenaud_interrupt,
					     0, "Stefano Alsa Card", info);
#else
	err = bind_evtchn_to_irqhandler(info->evtchn, xenaud_interrupt,
					   0, "Stefano Alsa Card", info);
#endif	
	if (err < 0)
		goto fail;
	info->irq = err;
	return 0;

fail:
	return err;
}

static void xenaud_disconnect_backend(struct audfront_info *info)
{
	/* Stop old i/f to prevent errors whilst we rebuild the state. */
	int i;

	printk(KERN_ERR "SSSS %s \n", __FUNCTION__);
	if (info->irq)
		unbind_from_irqhandler(info->irq, info);
	info->evtchn = info->irq = 0;

	/* TODO leaking the event channel! */

	for (i = 0; i < N_AUD_BUFFER_PAGES; i++) {
		if (playback_grefs[i] != GRANT_INVALID_REF)
			gnttab_end_foreign_access(playback_grefs[i], 0, (unsigned long)xc_playback_page[i]);
		capture_grefs[i] = GRANT_INVALID_REF;
		if (capture_grefs[i] != GRANT_INVALID_REF)
			gnttab_end_foreign_access(capture_grefs[i], 0, (unsigned long)xc_capture_page[i]);
		capture_grefs[i] = GRANT_INVALID_REF;
		
	}

	if (page_gref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(page_gref, 0, (unsigned long)af_info.shared_page);
		page_gref = GRANT_INVALID_REF;
	}
}

/* Common code used when first setting up, and when resuming. */
static int talk_to_audback(struct xenbus_device *dev, struct audfront_info *info)
{
	const char *message;
	struct xenbus_transaction xbt;
	int err;

	printk(KERN_ERR "SSSS %s \n", __FUNCTION__);
	/* Create shared ring, alloc event channel. */
	err = setup_audfront(dev, info);
	if (err)
		goto out;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ring;
	}

	err = xenbus_printf(xbt, dev->nodename, "page-ref", "%u",
			       info->tx_ring_ref);
	if (err) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename,
			       "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ring;
	}

	xenbus_switch_state(dev, XenbusStateInitialising);
	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, err, "%s", message);
destroy_ring:
	xenaud_disconnect_backend(&af_info);
out:
	return err;
}

void audfront_close(struct xenbus_device *dev)
{
	xenaud_disconnect_backend(&af_info);
	xenbus_frontend_closed(dev);
}

/**
 * Callback received when the backend's state changes.
 */
static void audback_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	printk(KERN_ERR "BK state %s\n", xenbus_strstate(backend_state));
	printk(KERN_ERR "FE state %s\n", xenbus_strstate(dev->state));

	switch (backend_state) {
	case XenbusStateUnknown:
		/* if the backend vanishes from xenstore, close frontend */
		/* if (!xc_xenbus_exists(XBT_NIL, dev->otherend, "")) { */
		/* 	if (dev->state != XenbusStateClosed) { */
		/* 		printk(KERN_INFO "backend vanished, closing frontend\n"); */
		/* 		audfront_close(dev); */
		/* 	} */
		/* } */
		break;
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	/* These states appeared some time back in the 2.6 days, not entirely
	 * clear what kernels they are in but this breaks Debian 6. Since they
	 * are not used anyway, just def them out in old kernels.
	 */
#if ( LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32) )
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
#endif
	case XenbusStateConnected:
		break;

	case XenbusStateInitWait:
		if (dev->state != XenbusStateInitialising && dev->state != XenbusStateClosed)
			break;
		printk(KERN_ERR "SSSS %s talking to back\n", __FUNCTION__);
		talk_to_audback(dev, &af_info);
		xenbus_switch_state(dev, XenbusStateConnected);
		alsa_card_xc_audio_init();
		break;

	case XenbusStateClosed:
	case XenbusStateClosing:
		if (dev->state != XenbusStateClosed)
			audfront_close(dev);
		else
			xenbus_switch_state(dev, XenbusStateInitialising);
		break;
	}
}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int fake_probe(struct xenbus_device *dev,
				const struct xenbus_device_id *id)
#else
static int __devinit fake_probe(struct xenbus_device *dev,
				const struct xenbus_device_id *id)
#endif
{
	printk(KERN_INFO "%s\n", __FUNCTION__);
	//talk_to_audback(dev, &af_info);
	return 0;
}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) )
static int fake_remove(struct xenbus_device *dev)
#else
static int __devexit fake_remove(struct xenbus_device *dev)
#endif
{
	printk(KERN_INFO "%s\n", __FUNCTION__);

	alsa_card_xc_audio_exit();

	xenbus_switch_state(dev, XenbusStateClosing);
	xenaud_disconnect_backend(&af_info);
	return 0;
}

static struct xenbus_driver audfront_driver = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
	/* In general, this is the kernel version where the switch over
	 * happened except for Debian 6's kernel which has both.. */
	.name = "vsnd",
	.owner = THIS_MODULE,
#else
	.driver.name = "vsnd",
	.driver.owner = THIS_MODULE,
#endif
	.ids = audfront_ids,
	.probe = fake_probe,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
	.remove = fake_remove,
#else
	.remove = __devexit_p(fake_remove),
#endif
	.resume = audfront_resume,
	.otherend_changed = audback_changed,
};

static int __init xc_audio_init(void)
{

	int rc = 0;

	mutex_lock(&xenaudio_pm_mutex);

	rc = xenbus_register_frontend(&audfront_driver);
	if (rc)
		goto out;

	printk(KERN_INFO "xen_audio initialized\n");
out:
	mutex_unlock(&xenaudio_pm_mutex);
	return rc;
}
module_init(xc_audio_init);


static void __exit xc_audio_exit(void)
{
	mutex_lock(&xenaudio_pm_mutex);
	xenbus_unregister_driver(&audfront_driver);
	mutex_unlock(&xenaudio_pm_mutex);
}
module_exit(xc_audio_exit);

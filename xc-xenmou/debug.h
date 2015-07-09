/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef DEBUG

#define DEBUG_MSG(...) printk(KERN_INFO __VA_ARGS__)
#define DEBUG_DO(x) x
#else
#define DEBUG_MSG(...) 
#define DEBUG_DO(x)
#endif

#ifdef DEBUG

#define KEY_MOUSE_START 0x110
char keyastr[][7]={"LEFT","RIGHT","MIDDLE","SIDE","EXTRA","FORWARD","BACK","TASK"};

#define KEY_DIGI_START 0x140
char keybstr[][15]={"TOOL_PEN","TOOL_RUBBER","TOOL_BRUSH","TOOL_PENCIL","TOOL_AIRBRUSH","TOOL_FINGER","TOOL_MOUSE","TOOL_LENS","TOOL_QUINTTAP","149","TOUCH","STYLUS","STYLUS2","TOOL_DOUBLETAP","TOOL_TRIPLETAP","TOOL_QUADTAP"};	

char typestr[][4] = {"SNC", "KEY", "REL", "ABS", "MSC", "SW "};
char relstr[][7]={"X","Y","Z","RX","RY","RZ","HWHEEL","DIAL","WHEEL","MISC"};

char absstr[][15]={
"X","Y","Z","RX","RY","RZ","THROTTLE","RUDDER","WHEEL","GAS","BRAKE"
,"0b", "0c", "0d", "0e", "0f",
"HAT0X","HAT0Y","HAT1X","HAT1Y","HAT2X","HAT2Y","HAT3X","HAT3Y","PRESSURE","DISTANCE","TILT_X","TILT_Y","TOOL_WIDTH","1d","1e","1f","Volume","21","22","23","24","25","26","27","MISC"
,"29", "2a", "2b", "2c", "2d", "2e",
"MT_SLOT","MT_TOUCH_MAJOR","MT_TOUCH_MINOR","MT_WIDTH_MAJOR","MT_WIDTH_MINOR","MT_ORIENTATION","MT_POSITION_X","MT_POSITION_Y","MT_TOOL_TYPE","MT_BLOB_ID","MT_TRACKING_ID","MT_PRESSURE","MT_DISTANCE"};

int testbits(struct input_dev *dev, int type, int code)
{

	if (!test_bit(type, dev->evbit))
	{
		printk("Event type not supported");
		return 0;
	}

	switch (type) {
	case EV_SYN:
		break;
	case EV_KEY:
		if (!test_bit(code, dev->keybit))
		{
		printk("Key Event not supported.");
		return 0;
		}
		break;
	case EV_REL:
		if (!test_bit(code, dev->relbit))
		{
		printk("Rel Event not supported.");
		return 0;
		}
		break;
	case EV_ABS:
		if (!test_bit(code, dev->absbit))
		{
		printk("Abs Event %x not supported.", code);
		return 0;
		}
		break;
	case EV_MSC:
		if (!test_bit(code, dev->mscbit))
		{
		printk("MSC Event not supported.");
		return 0;
		}
		break;
	default:
		printk("Not expected code.");
		return 0;
	}
	return 1;
}

static void debug_packet(int slot, int type, int code, int value)
{
   char outstr[80];

   if ((type==0) && (code==0))
	sprintf(outstr, "-sync----------\n");
   else if ((type==1) && (code>(KEY_MOUSE_START-1)) && (code<0x118))
	sprintf(outstr, "Button %s v 0x%x\n", keyastr[code-KEY_MOUSE_START], value);
   else if ((type==1) && (code>(KEY_DIGI_START-1)) && (code<0x150))
	sprintf(outstr, "Button %s v 0x%x\n", keybstr[code-KEY_DIGI_START], value);
   else if ((type==2) && (code<0xa))
	sprintf(outstr, "Rel %s v 0x%x\n", relstr[code], value);
   else if ((type==3) && (code<0x3c))
	sprintf(outstr, "Abs %s v 0x%x\n", absstr[code], value);
   else
	{
	if ( type<6)
		sprintf(outstr, "%s c %x v 0x%x\n", typestr[type], code, value);
	else
		sprintf(outstr, "(0x%x) c %x v 0x%x\n", type, code, value);

	}
	
   printk (KERN_INFO "%d: %s",slot, outstr);
}


#define show_garbage_list {int i; for (i=0; i<gl.listcount; i++) { debug_packet(interface, gl.typelist[i], gl.codelist[i], gl.countlist[i]);	} gl.listcount=0;}

#define typelistlength 20
struct garbage_list
{
  int garbagecount;
  int typelist[typelistlength];
  int codelist[typelistlength];
  int countlist[typelistlength];
  int listcount;
  int show_no_slot;
};

#define DEBUG_INIT static struct garbage_list gl = {.garbagecount=0, .listcount=0,  .show_no_slot = true};

#define DEBUG_DEV_SET													\
	if (!idev)                                                                                                      \
		 {													\
		 DEBUG_MSG("XenMou: Switching away from bad slot.  There where %d packets ignored.\n", gl.garbagecount); \
		 show_garbage_list;											\
		 } \
	gl.garbagecount=0;												\
        gl.show_no_slot = true; 


#define DEBUG_SWITCH_DEV 												\
		DEBUG_MSG("XenMOu: Switch to slot %d. %d packets lost.\n",interface, gl.garbagecount); 			\
		show_garbage_list; 											\
		} 													\
	     else 													\
		{ 													\
		if (gl.show_no_slot) 											\
			{ 												\
			printk (KERN_INFO "XenMOu: Could not switch to slot %d\n",interface); 				\
			gl.show_no_slot=false; 										\
			} 

#ifdef VERBOSE
#define DEBUG_AND_input_event DEBUG_AND_input_event_A DEBUG_AND_input_event_BV DEBUG_AND_input_event_C
#define DEBUG_PACKET debug_packet(interface, pd.type, pd.code, pd.value);
#else
#define DEBUG_AND_input_event DEBUG_AND_input_event_A DEBUG_AND_input_event_B  DEBUG_AND_input_event_C
#define DEBUG_PACKET
#endif

#define DEBUG_AND_input_event_A								\
	         if (testbits(idev,pd.type, pd.code))				\
		    {									\
                    input_event(idev, pd.type, pd.code, pd.value);		\
		    }									\
	         else

#define DEBUG_AND_input_event_BV							\
		    printk("Following event is not supported\n");			\
		debug_packet(interface, pd.type, pd.code, pd.value );		\

#define DEBUG_AND_input_event_B								\
		    {									\
		    printk("Following event is not supported\n");			\
		    debug_packet(interface, pd.type, pd.code, pd.value );	\
		    }									\

#define DEBUG_AND_input_event_C								\
	         } /* else not ABS_MT_TRACK_ID */					\
            } /* idev */								\
        else										\
            {										\
            int found=0, i;								\
            gl.garbagecount++;								\
											\
            if (gl.listcount<typelistlength)						\
              {										\
		for (i=0; i<gl.listcount; i++)						\
		{									\
		if ((gl.typelist[i]==pd.type) && (gl.codelist[i]==pd.code))	\
			{								\
			found=1;							\
		gl.countlist[i]++;						\
			break;								\
			}								\
		}									\
		if (!found)								\
		{									\
		gl.typelist[gl.listcount]=pd.type;					\
		gl.codelist[gl.listcount]=pd.code;					\
		gl.countlist[gl.listcount]=1;						\
		gl.listcount++;								\
                }									\
              }


#else
#define DEBUG_INIT
#define DEBUG_DEV_SET
#define DEBUG_SWITCH_DEV
#define DEBUG_PACKET
#endif



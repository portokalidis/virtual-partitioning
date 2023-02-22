Copyright (c) 2012, Dimitris Geneiatakis (d.geneiatakis@gmail.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of the Columbia University nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



#include <iostream>
#include <set>
#include <map>
#include <cassert>
#include <fstream>
#include <vector>
#include <fstream>
#include <iomanip>

#include "pin.H"

extern "C" {
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
}

//#define BRANCH
//#define RELATE
#define RET
#define INSTRUCTION
//#define ROUTINE


string invalid ="invalid_rtn";



/*
 * Inject code after rtn.
 * We record
 * img name, 
 * rtn offset from the start of img,
 * return value
 *
 */

static VOID rtn_after(const string *img_name, ADDRINT offset, ADDRINT value, string *s )
{
	FILE *fp=fopen("/home/dgen/svn/switch/trunk/calltrace/rtn-after.txt","a");	
	if((int)value>-1)
		fprintf(fp,"%s-%d-%s,%d\n",img_name->c_str(),(int)offset,s->c_str(),(int)value);
	fclose(fp);
}



static VOID ins_branch(const string *img_name,ADDRINT branch_offset,INT32 taken)
{
	FILE *fp=fopen("/home/dgen/svn/switch/trunk/calltrace/ins_branch.txt","a");	
	fprintf(fp,"%s-%d,%d\n",img_name->c_str(),(int)branch_offset,(int)taken);
	fclose(fp);
}

static VOID ins_ret_f(const string *img_name,ADDRINT branch_offset,INT32 taken,string *s)
{
	FILE *fp=fopen("/home/dgen/svn/switch/trunk/calltrace/ins_ret.txt","a");	
	fprintf(fp,"%s-%d-%s,%d\n",img_name->c_str(),(int)branch_offset,s->c_str(),(int)taken);
	fclose(fp);
}

static VOID relate(ADDRINT addr, string *rname)
{
	
	string rtn_name;
	rtn_name=RTN_FindNameByAddress(addr);

	FILE *fp=fopen("/home/dgen/svn/switch/trunk/calltrace/rtn-relate.txt","a");	

	if(rtn_name.compare(0,1,".")==0 
		|| rname->compare(0,1,".")==0 
		|| rtn_name.compare(*rname)==0 
		|| rtn_name.compare("")==0 || rname->compare("")==0){
		//do not record these functions
	}
	else{
		fprintf(fp,"%s,%s\n",rname->c_str(),rtn_name.c_str());
	}
	
	fclose(fp);


}

////////////////////////////////////////////////////
//	Instrumentation
////////////////////////////////////////////////////

/*Both INS_Relation and RTN_Relation create the call
 pairs among functions
e.g., 
A,B
B,A
*/

VOID INS_Relation(INS ins, VOID *v)
{
	RTN rtn;
	string *rtn_name;
		
	if(INS_IsCall(ins))
	{
		rtn=INS_Rtn(ins);		
		if(RTN_Valid(rtn))
			rtn_name=new string(RTN_Name(rtn));
		else{
			rtn_name=new string("invalid rtn name");
		}

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)relate,IARG_BRANCH_TARGET_ADDR,IARG_PTR,rtn_name,IARG_END);
	}
}

VOID RTN_Relation(RTN rtn, VOID *v)
{
	
	string *rtn_name;
	ADDRINT addr;


	if(RTN_Valid(rtn)){
		RTN_Open(rtn);
		for(INS ins=RTN_InsHead(rtn); INS_Valid(ins); ins=INS_Next(ins)){
			if(INS_IsCall(ins))
			{
				rtn_name=new string(RTN_Name(rtn));
				INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)relate,IARG_BRANCH_TARGET_ADDR,IARG_PTR,rtn_name,IARG_END);
			}
		}
		RTN_Close(rtn);
	}
}


VOID RTN_Instrument(RTN rtn, VOID *v)
{
	string *s;
	string tmp1;
	string *rname;
	string *img_name;

	ADDRINT img_low_addr;
	ADDRINT img_high_addr;
	ADDRINT rtn_addr;
	ADDRINT rtn_offset;


	RTN_Open(rtn);


	if(RTN_Valid(rtn)){

		for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)){
		
			img_low_addr=IMG_LowAddress(img);
			img_high_addr=IMG_HighAddress(img);
			img_name= new string (IMG_Name(img));

			rtn_addr=RTN_Address(rtn);
			if( rtn_addr >= img_low_addr && rtn_addr<=img_high_addr){
				 
				rtn_offset= rtn_addr-img_low_addr;
		
				s= new string(RTN_Name(rtn));

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtn_after,
						IARG_PTR, img_name,IARG_ADDRINT,rtn_offset,IARG_FUNCRET_EXITPOINT_VALUE,IARG_PTR,s,
						IARG_END);

			}

		}
	
	}

	RTN_Close(rtn);


}

VOID INS_Instrument(INS ins,VOID *v)
{
	
	string *rtn_name;
	string *img_name;
	ADDRINT img_low_addr;
	ADDRINT img_high_addr;
	
	ADDRINT addr_ins;
	ADDRINT addr_ins_offset;

#ifdef BRANCH
	if(INS_IsBranch(ins)){
		
		addr_ins = INS_Address(ins);
		for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)){
			
			img_low_addr=IMG_LowAddress(img);
			img_high_addr=IMG_HighAddress(img);
			img_name= new string (IMG_Name(img));

			 if( addr_ins>=img_low_addr && addr_ins<=img_high_addr){
				 addr_ins_offset= addr_ins-img_low_addr;
			         
				 RTN rtn = INS_Rtn(ins);
				 rtn_name = new string (RTN_Name(rtn));
				
				  INS_InsertCall(ins,IPOINT_BEFORE, AFUNPTR(ins_branch),IARG_PTR,img_name,
			                       IARG_ADDRINT,addr_ins_offset,IARG_BRANCH_TAKEN,IARG_END);
			 }

		 }

	}
#endif

#ifdef RET
	if(INS_IsRet(ins)){



		addr_ins = INS_Address(ins);
		for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)){
			
			img_low_addr=IMG_LowAddress(img);
			img_high_addr=IMG_HighAddress(img);
			img_name= new string (IMG_Name(img));

			 if( addr_ins>=img_low_addr && addr_ins<=img_high_addr){
				 addr_ins_offset= addr_ins-img_low_addr;
			         
				 RTN rtn = INS_Rtn(ins);
				 rtn_name = new string (RTN_Name(rtn));
				

			  INS_InsertCall(ins,IPOINT_BEFORE, AFUNPTR(ins_ret_f),IARG_PTR,img_name,
			                       IARG_ADDRINT,addr_ins_offset,
					       IARG_FUNCRET_EXITPOINT_VALUE,IARG_PTR,rtn_name,
					       IARG_END);
			}
		}
	}
#endif



}

/*There are cases where applications crash when we do the record. 
 * This is because of the way they we handle descriptors: 
 * In the current code version we open and close after any intrusction which we
 * monitor. sshd works on this 'mode'
 * Other cases require to keep steadily the file descriptor open (e.g smbd)
 * */


int 
main(int argc, char **argv)
{

//	fp_rtn=fopen("/home/dgen/svn/switch/trunk/calltrace/rtn-after.txt","a");	

	PIN_InitSymbols();

	//Initialize Pin
	if (PIN_Init(argc, argv)) {
		PIN_ExitProcess(1);
	}

#ifdef INSTRUCTION
	INS_AddInstrumentFunction(INS_Instrument,0);
#endif 
//the following function implements the same functionality 
//is able to record the function name and the return value 
#ifdef ROUTINE
	RTN_AddInstrumentFunction(RTN_Instrument,0);
#endif 

#ifdef	RELATE
	INS_AddInstrumentFunction(INS_Relation,0);
//the following function implements the same functionality
//	RTN_AddInstrumentFunction(RTN_Relation,0);
#endif 


	PIN_StartProgram();

	return 0;
}

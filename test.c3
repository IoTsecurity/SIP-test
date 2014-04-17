/*
 * test.c
 *
 *  Created on: 2014年3月4日
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"

int main()
{
	RegisterContext * RegisterCon;

RegisterCon=(RegisterContext*)malloc(sizeof(RegisterContext)+300);
if(RegisterCon==NULL)
	printf("malloc error\n");
printf("enter\n");
	//int fd=open(file,O_RDONLY);
	   // if(fd>2){   //确保文件存在
	    	//static  char * cfgFile ;
	    	//cfgFile=(char *)malloc(sizeof(char)*30);
	    	//strcpy(cfgFile,file);
	    	//device_info.cfgFile=cfgFile;

	    	char *value=(char *)malloc(sizeof(char)*20);
	    	value="65656565";
	    	char * p=RegisterCon;
	    	RegisterCon->radius_id=p+sizeof(RegisterContext);
	    	RegisterCon->peer_id=RegisterCon->radius_id+20;
	    	RegisterCon->peer_ip=RegisterCon->radius_id+40;
	    	RegisterCon->self_id=RegisterCon->radius_id+60;
	    	RegisterCon->self_password=RegisterCon->radius_id+80;
	    	RegisterCon->peer_password=RegisterCon->radius_id+100;
	    	//debug_w("+1\n");
	    	//get_conf_value( "radius_id",value,file);debug_w("+1.0\n");
	    	printf("enter1\n");
	    	memcpy(RegisterCon->peer_ip,value,20);
	    	printf("enter2\n");
	    	printf("%s\n",RegisterCon->peer_ip);
return 1;
}


/*
 * test.c
 *
 *  Created on: 2014年1月8日
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"
/*
int main3()
{
	int i=0;

	unsigned char *ECDH_keydata; // shared secret
	RegisterContext *rc=(RegisterContext *)malloc(sizeof(RegisterContext));;
	AccessAuthRequ *access_auth_requ_packet=(AccessAuthRequ *)malloc(sizeof(AccessAuthRequ));;
	AccessAuthResp *access_auth_resp_packet=(AccessAuthResp *)malloc(sizeof(AccessAuthResp));;
	printf("sizeof(rc->keydata):%d\n",sizeof(rc->keydata));
	printf("-1\n");
	memcpy(&rc->keydata, genECDHtemppubkey(), sizeof(rc->keydata));
	memcpy(&access_auth_requ_packet->asuekeydata, &rc->keydata, sizeof(access_auth_requ_packet->asuekeydata));
printf("0\n");

	char *keydata;
	keydata=&access_auth_requ_packet->asuekeydata;
	printf("keydata %d:\n",sizeof(access_auth_requ_packet->asuekeydata));
	for(i=0;i<32;i++)
	{
		printf("%02x ",(unsigned char)keydata[i]);
	}printf("\n");

	memcpy(&rc->keydata, genECDHtemppubkey(), sizeof(rc->keydata));
	memcpy(&access_auth_resp_packet->aekeydata, &rc->keydata, sizeof(access_auth_resp_packet->aekeydata));
	size_t secretlen=KEY_LEN;


	i=0;
	unsigned char p[32];
	//p[i++]=0x98; p[i++]=0x01;p[i++]=0x00;p[i++]=0x00;p[i++]=0x98;p[i++]=0x01;p[i++]=0x00;p[i++]=0x00;
	//p[i++]=0x01;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0xa0;p[i++]=0xbe;p[i++]=0x5f;p[i++]=0x00;
	//p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0xb8;p[i++]=0x25;p[i++]=0x1c;p[i++]=0x08;
	//p[i++]=0x01;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;p[i++]=0x00;
	//p[i++]=0x98; p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x98 ; p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ;
	//p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0xa0 ; p[i++]=0xce ; p[i++]=0x5e ; p[i++]=0x00 ;
	//p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0xda ; p[i++]=0xb4 ; p[i++]=0x09 ;
	//p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00;

	p[i++]=0x98 ; p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x98 ; p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ;
	p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0xa0 ; p[i++]=0x6e ; p[i++]=0x73 ; p[i++]=0x00 ;
	p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x4a ; p[i++]=0xa5 ; p[i++]=0x08 ;
	p[i++]=0x01 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00 ; p[i++]=0x00;
	printf("i=%d p[i]:\n",i);
	for(i=0;i<64;i++)
	{
		printf("%02x ",p[i]);
	}printf("\n");

	memcpy(p,&access_auth_requ_packet->asuekeydata,32);
	printf("i=%d p[i]:\n",i);
	for(i=0;i<64;i++)
	{
		printf("%02x ",p[i]);
	}printf("\n");
//memset(p,0,32);

	printf("11111\n");
	ECDH_keydata = genECDHsharedsecret(&rc->keydata, (EVP_PKEY *)p, &secretlen);
	printf("22222\n");
	return 1;
	}
*/
int main()
{

	RegisterContext *rc_s=(RegisterContext *)malloc(sizeof(RegisterContext));
	memcpy(rc_s->radius_id,"0",2);
	memcpy(rc_s->peer_id,"11111",6);
	memcpy(rc_s->peer_ip,"192.168.17.127",16);
	memcpy(rc_s->self_id,"2",2);
	memcpy(rc_s->self_password,"aaa",4);
	memcpy(rc_s->peer_password,"123456",7);

	rc_s->self_MACaddr.macaddr[0]=0x00;
	rc_s->self_MACaddr.macaddr[1]=0x0c;
	rc_s->self_MACaddr.macaddr[2]=0x29;
	rc_s->self_MACaddr.macaddr[3]=0xd4;
	rc_s->self_MACaddr.macaddr[4]=0x25;
	rc_s->self_MACaddr.macaddr[5]=0x3e;

	rc_s->peer_MACaddr.macaddr[0]=0x00;
	rc_s->peer_MACaddr.macaddr[1]=0x0c;
	rc_s->peer_MACaddr.macaddr[2]=0x29;
	rc_s->peer_MACaddr.macaddr[3]=0xd4;
	rc_s->peer_MACaddr.macaddr[4]=0x25;
	rc_s->peer_MACaddr.macaddr[5]=0x3e;

	Keybox.nkeys=0;

	RegisterContext *rc_c=(RegisterContext *)malloc(sizeof(RegisterContext));

	memcpy(rc_c->radius_id,"0",2);
	memcpy(rc_c->peer_id,"2",2);
	memcpy(rc_c->peer_ip,"192.168.17.127",16);
	memcpy(rc_c->self_id,"11111",6);
	memcpy(rc_c->self_password,"123456",7);
	memcpy(rc_c->peer_password,"aaa",4);

	rc_c->self_MACaddr.macaddr[0]=0x00;
	rc_c->self_MACaddr.macaddr[1]=0x0c;
	rc_c->self_MACaddr.macaddr[2]=0x29;
	rc_c->self_MACaddr.macaddr[3]=0xd4;
	rc_c->self_MACaddr.macaddr[4]=0x25;
	rc_c->self_MACaddr.macaddr[5]=0x3e;

	rc_c->peer_MACaddr.macaddr[0]=0x00;
	rc_c->peer_MACaddr.macaddr[1]=0x0c;
	rc_c->peer_MACaddr.macaddr[2]=0x29;
	rc_c->peer_MACaddr.macaddr[3]=0xd4;
	rc_c->peer_MACaddr.macaddr[4]=0x25;
	rc_c->peer_MACaddr.macaddr[5]=0x3e;
	Keybox.nkeys=0;

	printf("start\n");
	//----------------server send 401 Unauthorized packet--------------------------------------------
	Self_type=SIPserver;
	AuthActive *auth_active_packet_s=(AuthActive *)malloc(sizeof(AuthActive)*2);
	ProcessWAPIProtocolAuthActive(rc_s,auth_active_packet_s);
	codeTOChar(auth_active_packet_s,sizeof(AuthActive)*2);
	printf("server send 401 Unauthorized packet---------finished\n");

	//---------------client    send Register ( access auth request packet )-------------------------------------
	Self_type=IPC;
	AuthActive *auth_active_packet_c=(AuthActive *)malloc(sizeof(AuthActive)*2);
	//memcpy(auth_active_packet_c,auth_active_packet_s,sizeof(AuthActive)*2);
	memcpy(auth_active_packet_c,auth_active_packet_s,sizeof(AuthActive)*2);
	decodeFromChar(auth_active_packet_c,sizeof(AuthActive)*2);
decodeFromChar(auth_active_packet_s,sizeof(AuthActive)*2);
	HandleWAPIProtocolAuthActive(rc_c,auth_active_packet_c);
	//printf("c-s 2 finish HandleWAPIProtocolAuthActive\n");
	AccessAuthRequ *access_auth_requ_packet_c=(AccessAuthRequ *)malloc(sizeof(AccessAuthRequ)*2);
	memset(access_auth_requ_packet_c,0,sizeof(AccessAuthRequ)*2);
	ProcessWAPIProtocolAccessAuthRequest(rc_c,auth_active_packet_c,access_auth_requ_packet_c);
	codeTOChar(access_auth_requ_packet_c,sizeof(AccessAuthRequ)*2);
	printf("client    send Register ( access auth request packet ) ----------------------finish\n");


	//-----------------------server   send the Access-Request ( cert auth request packet )--------------------------------------
	Self_type=SIPserver;
	AccessAuthRequ *access_auth_requ_packet_s=(AccessAuthRequ *)malloc(sizeof(AccessAuthRequ)*2);
	memcpy(access_auth_requ_packet_s,access_auth_requ_packet_c,sizeof(AccessAuthRequ)*2);
	decodeFromChar(access_auth_requ_packet_s,sizeof(AccessAuthRequ)*2);
decodeFromChar(access_auth_requ_packet_c,sizeof(AccessAuthRequ)*2);
	HandleWAPIProtocolAccessAuthRequest(rc_s,auth_active_packet_s,access_auth_requ_packet_s);
	printf("s-c 3 HandleWAPIProtocolAccessAuthRequest\n");
	CertificateAuthRequ *certificate_auth_requ_packet_s=(CertificateAuthRequ *)malloc(sizeof(CertificateAuthRequ));
	printf("before ProcessWAPIProtocolCertAuthRequest\n");
	ProcessWAPIProtocolCertAuthRequest(rc_s,access_auth_requ_packet_s,certificate_auth_requ_packet_s);

//add lvshichao's interface
//printf("---------------wait for interface----------------------\n");
CertificateAuthResp *certificate_auth_resp_packet_s=(CertificateAuthResp *)malloc(sizeof(CertificateAuthResp));
if(talk_to_asu(certificate_auth_requ_packet_s,certificate_auth_resp_packet_s)<0)
{
	printf("talk_to_asu error \n");
	}
printf("server   send the Access-Request ( cert auth request packet )----------------finished\n");


//----------------server send 200OK/403 Forbidden ( access auth response packet ) SUCCESS/FAILUE-----------------------------

AccessAuthResp *access_auth_resp_packet_s=(AccessAuthResp *)malloc(sizeof(AccessAuthResp));
if(HandleProcessWAPIProtocolCertAuthResp(rc_s,certificate_auth_requ_packet_s,
		certificate_auth_resp_packet_s,access_auth_resp_packet_s)<1)
{
	printf("HandleProcessWAPIProtocolCertAuthResp error\n");
}
printf("HandleProcessWAPIProtocolCertAuthResp ---------------------finished\n");
if(ProcessWAPIProtocolAccessAuthResp(rc_s,
		access_auth_requ_packet_s, access_auth_resp_packet_s)<1)
{
	printf("ProcessWAPIProtocolAccessAuthResp error\n");
	}
printf("server send 200OK/403 Forbidden ( access auth response packet ) SUCCESS/FAILUE------------finished\n");

//----------------------client handle the access auth response packet---------------------------

	Self_type=IPC;
	AccessAuthResp *access_auth_resp_packet_c=(AccessAuthResp *)malloc(sizeof(AccessAuthResp));
	memcpy(access_auth_resp_packet_c,access_auth_resp_packet_s,sizeof(AccessAuthResp));
	if(HandleWAPIProtocolAccessAuthResp(rc_c,access_auth_requ_packet_c,access_auth_resp_packet_c)<1)
	{
		printf("HandleWAPIProtocolAccessAuthResp error\n");
	}
	printf("client handle the access auth response packet------------finished\n");


	printf("-----------register finished---------------");

	// key negorequest
	//int ProcessUnicastKeyNegoRequest(RegisterContext *rc, UnicastKeyNegoRequ *unicast_key_nego_requ_packet);
	//int HandleUnicastKeyNegoRequest(RegisterContext *rc, const UnicastKeyNegoRequ *unicast_key_nego_requ_packet);



}

int codeTOChar(char *data,int lenth)
{
	int i,j;
	i=lenth-1;
	j=lenth/2-1;
	for(i=lenth-1;i>=0;i=i-2,j--)
	{
		data[i]=(data[j]&0x0f)+0x30;
		data[i-1] = ((data[j]>>4)&0x0f)+0x30;
	}
	return 0;
}
int decodeFromChar(char *data,int lenth)
{
	int i,j;
	i=1;
	j=0;
	for(j=0;i<lenth ;i=i+2,j++)
	{
		data[j]=(data[i] - 0x30 ) +((data[i-1]-0x30) <<4);
	}
	return 0;
}

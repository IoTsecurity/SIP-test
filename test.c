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
#include "test.h"

KeyBox KeyboxIPC;
KeyBox KeyboxNVR;
KeyBox KeyboxSIPserver;

SecureLinks SecurelinksIPC;
SecureLinks SecurelinksNVR;
SecureLinks SecurelinksSIPserver;

int main()
{

	RegisterContext *rc_s=(RegisterContext *)malloc(sizeof(RegisterContext));
	memcpy(rc_s->radius_id,"0",2);
	memcpy(rc_s->peer_id,"11111",6);
	memcpy(rc_s->peer_ip,"192.168.17.127",16);
	memcpy(rc_s->self_id,"2",2);
	memcpy(rc_s->self_password,"aaa",4);
	memcpy(rc_s->peer_password,"123456",7);

	memcpy(rc_s->self_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);
	memcpy(rc_s->peer_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);

	Keybox.nkeys=0;
	KeyboxIPC.nkeys=0;
	KeyboxNVR.nkeys=0;
	KeyboxSIPserver.nkeys=0;

	RegisterContext *rc_c=(RegisterContext *)malloc(sizeof(RegisterContext));

	memcpy(rc_c->radius_id,"0",2);
	memcpy(rc_c->peer_id,"2",2);
	memcpy(rc_c->peer_ip,"192.168.17.127",16);
	memcpy(rc_c->self_id,"11111",6);
	memcpy(rc_c->self_password,"123456",7);
	memcpy(rc_c->peer_password,"aaa",4);

	memcpy(rc_c->self_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);
	memcpy(rc_c->peer_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);

	Keybox.nkeys=0;

	printf("start\n");
	//----------------server send 401 Unauthorized packet--------------------------------------------
	changeTo(IPC,SIPserver);
	AuthActive *auth_active_packet_s=(AuthActive *)malloc(sizeof(AuthActive)*2);
	ProcessWAPIProtocolAuthActive(rc_s,auth_active_packet_s);
	codeTOChar(auth_active_packet_s,sizeof(AuthActive)*2);
	printf("server send 401 Unauthorized packet---------finished\n");

	//---------------client    send Register ( access auth request packet )-------------------------------------
	changeTo(SIPserver,IPC);
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
	changeTo(IPC,SIPserver);
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
		return 0;
		}
	printf("server   send the Access-Request ( cert auth request packet )----------------finished\n");


	//----------------server send 200OK/403 Forbidden ( access auth response packet ) SUCCESS/FAILUE-----------------------------

	AccessAuthResp *access_auth_resp_packet_s=(AccessAuthResp *)malloc(sizeof(AccessAuthResp));
	if(HandleProcessWAPIProtocolCertAuthResp(rc_s,certificate_auth_requ_packet_s,
			certificate_auth_resp_packet_s,access_auth_resp_packet_s)<1)
	{
		printf("HandleProcessWAPIProtocolCertAuthResp error\n");
		return 0;
	}
	printf("HandleProcessWAPIProtocolCertAuthResp ---------------------finished\n");
	if(ProcessWAPIProtocolAccessAuthResp(rc_s,
			access_auth_requ_packet_s, access_auth_resp_packet_s)<1)
	{
		printf("ProcessWAPIProtocolAccessAuthResp error\n");
		return 0;
		}
	printf("server send 200OK/403 Forbidden ( access auth response packet ) SUCCESS/FAILUE------------finished\n");

	//----------------------client handle the access auth response packet---------------------------

	changeTo(SIPserver,IPC);
	AccessAuthResp *access_auth_resp_packet_c=(AccessAuthResp *)malloc(sizeof(AccessAuthResp));
	memcpy(access_auth_resp_packet_c,access_auth_resp_packet_s,sizeof(AccessAuthResp));
	if(HandleWAPIProtocolAccessAuthResp(rc_c,access_auth_requ_packet_c,access_auth_resp_packet_c)<1)
	{
		printf("HandleWAPIProtocolAccessAuthResp error\n");
		return 0;
	}
	printf("client handle the access auth response packet------------finished\n");


	printf("-----------register finished---------------\n");




	printf("-----------nego begin---------------\n");
	// key negorequest
	printf("1-----in the server----\n");
	changeTo(IPC,SIPserver);
	UnicastKeyNegoRequ *unicast_key_nego_requ_packet_s=(UnicastKeyNegoRequ*)malloc (sizeof(UnicastKeyNegoRequ));
	if(ProcessUnicastKeyNegoRequest(rc_s, unicast_key_nego_requ_packet_s)<1)
	{
		printf("ProcessUnicastKeyNegoRequest error\n");
		return 0;
	}

	printf("2-----in the IPC----\n");
	changeTo(SIPserver,IPC);
	UnicastKeyNegoRequ *unicast_key_nego_requ_packet_c=(UnicastKeyNegoRequ*)malloc (sizeof(UnicastKeyNegoRequ));
	memcpy(unicast_key_nego_requ_packet_c,unicast_key_nego_requ_packet_s,sizeof(UnicastKeyNegoRequ));
	if(HandleUnicastKeyNegoRequest(rc_c, unicast_key_nego_requ_packet_c)<1)
	{
		printf("HandleUnicastKeyNegoRequest error\n");
		return 0;
	}

	UnicastKeyNegoResp *unicast_key_nego_resp_packet_c=(UnicastKeyNegoResp*)malloc (sizeof(UnicastKeyNegoResp));
	if(ProcessUnicastKeyNegoResponse(rc_c, unicast_key_nego_resp_packet_c)<1)
	{
		printf("ProcessUnicastKeyNegoResponse error\n");
		return 0;
	}

	printf("3-----in the server----\n");
	changeTo(IPC,SIPserver);
	UnicastKeyNegoResp *unicast_key_nego_resp_packet_s=(UnicastKeyNegoResp*)malloc (sizeof(UnicastKeyNegoResp));
	memcpy(unicast_key_nego_resp_packet_s,unicast_key_nego_resp_packet_c,sizeof(UnicastKeyNegoResp));
	if(HandleUnicastKeyNegoResponse(rc_s,unicast_key_nego_resp_packet_s)<1)
	{
		printf("HandleUnicastKeyNegoResponse error\n");
		return 0;
	}

	UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet_s=(UnicastKeyNegoConfirm*)malloc (sizeof(UnicastKeyNegoConfirm));
	if(ProcessUnicastKeyNegoConfirm(rc_s,unicast_key_nego_confirm_packet_s)<1)
	{
		printf("ProcessUnicastKeyNegoConfirm error\n");
		return 0;
	}

	printf("4-----in the IPC----\n");
	changeTo(SIPserver,IPC);
	UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet_c=(UnicastKeyNegoConfirm*)malloc (sizeof(UnicastKeyNegoConfirm));
	memcpy(unicast_key_nego_confirm_packet_c,unicast_key_nego_confirm_packet_s,sizeof(UnicastKeyNegoConfirm));
	if(HandleUnicastKeyNegoConfirm(rc_c,unicast_key_nego_confirm_packet_c)<1)
	{
		printf("HandleUnicastKeyNegoConfirm error\n");
		return 0;
	}
	printf("----------------------------nego finished---------------------------------\n");



	printf("----------------------------distribute begin---------------------------------\n");

	printf("1-----in the SIPserver----\n");
	changeTo(IPC,SIPserver);
	Keybox.nkeys++;
	memcpy(Keybox.keyrings[Keybox.nkeys-1].partner_id,"user2",MAXIDSTRING);
	memset(Keybox.keyrings[Keybox.nkeys-1].CK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].IK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].KEK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].MasterKey,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].reauth_IK,1,KEY_LEN);

	RegisterContext *rc_s2NVR=(RegisterContext *)malloc(sizeof(RegisterContext));

	memcpy(rc_s2NVR->peer_id,"user2",6);
	memcpy(rc_s2NVR->peer_ip,"192.168.17.127",16);
	memcpy(rc_s2NVR->self_id,"2",2);

	memcpy(rc_s2NVR->self_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);
	memcpy(rc_s2NVR->peer_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);

	P2PLinkContext *lc_to_IPC=(P2PLinkContext *)malloc(sizeof(P2PLinkContext));
	P2PLinkContext *lc_to_NVR=(P2PLinkContext *)malloc(sizeof(P2PLinkContext));
	P2PLinkContext_Conversion_S(rc_s, rc_s2NVR, lc_to_IPC, lc_to_NVR);

	printf("ProcessP2PKeyDistribution for NVR\n");
	P2PKeyDistribution *p2p_key_dist_packet_to_NVR=(P2PKeyDistribution *)malloc(sizeof(P2PKeyDistribution));;
	if(ProcessP2PKeyDistribution(lc_to_NVR, p2p_key_dist_packet_to_NVR)<1)
	{
		printf("ProcessP2PKeyDistribution error\n");
		return 0;
	}

	printf("ProcessP2PKeyDistribution for IPC\n");
	P2PKeyDistribution *p2p_key_dist_packet_to_IPC=(P2PKeyDistribution *)malloc(sizeof(P2PKeyDistribution));
	if(ProcessP2PKeyDistribution(lc_to_IPC, p2p_key_dist_packet_to_IPC)<1)
	{
		printf("ProcessP2PKeyDistribution error\n");
		return 0;
	}

	printf("2-----in the IPC----\n");
	changeTo(SIPserver,IPC);
	P2PLinkContext *lc_in_IPC=(P2PLinkContext *)malloc(sizeof(P2PLinkContext));
	P2PLinkContext_Conversion_C(rc_c, lc_in_IPC,NVR);

	P2PKeyDistribution *p2p_key_dist_packet_in_IPC=(P2PKeyDistribution *)malloc(sizeof(P2PKeyDistribution));
	memcpy(p2p_key_dist_packet_in_IPC, p2p_key_dist_packet_to_IPC, sizeof(P2PKeyDistribution));
	if(HandleP2PKeyDistribution(lc_in_IPC, p2p_key_dist_packet_in_IPC)<1)
	{
		printf("HandleP2PKeyDistribution error\n");
		return 0;
	}


	printf("3-----in the NVR----\n");
	changeTo(IPC,NVR);
	Keybox.nkeys++;
	memcpy(Keybox.keyrings[Keybox.nkeys-1].partner_id,"2",MAXIDSTRING);
	memset(Keybox.keyrings[Keybox.nkeys-1].CK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].IK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].KEK,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].MasterKey,1,KEY_LEN);
	memset(Keybox.keyrings[Keybox.nkeys-1].reauth_IK,1,KEY_LEN);

	RegisterContext *rc_c_in_NVR=(RegisterContext *)malloc(sizeof(RegisterContext));

	memcpy(rc_c_in_NVR->peer_id,"2",6);
	memcpy(rc_c_in_NVR->peer_ip,"192.168.17.127",16);
	memcpy(rc_c_in_NVR->self_id,"user2",6);

	memcpy(rc_c_in_NVR->self_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);
	memcpy(rc_c_in_NVR->peer_MACaddr.macaddr,"\x00\x0c\x29\xd4\x25\x3e",6);

	P2PLinkContext *lc_in_NVR=(P2PLinkContext *)malloc(sizeof(P2PLinkContext));
	P2PLinkContext_Conversion_C(rc_c_in_NVR, lc_in_NVR, IPC);

	P2PKeyDistribution *p2p_key_dist_packet_in_NVR=(P2PKeyDistribution *)malloc(sizeof(P2PKeyDistribution));
	memcpy(p2p_key_dist_packet_in_NVR, p2p_key_dist_packet_to_NVR, sizeof(P2PKeyDistribution));
	if(HandleP2PKeyDistribution(lc_in_NVR, p2p_key_dist_packet_in_NVR)<1)
	{
		printf("HandleP2PKeyDistribution error\n");
	}

	printf("----------------------------distribute finished---------------------------------\n");

	printf("----------------------------p2p communicate begin---------------------------------\n");
	printf("-------------------p2p authentication token begin--------------------\n");
	printf("1-----in the IPC----\n");
	changeTo(NVR,IPC);

	P2PCommContext *cc_in_IPC=(P2PCommContext *)malloc(sizeof(P2PCommContext));memset(cc_in_IPC,0,sizeof(P2PCommContext));
	P2PCommContext_Conversion(lc_in_IPC, cc_in_IPC);

	P2PAuthToken *p2p_auth_token_in_IPC=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PAuthToken(cc_in_IPC, p2p_auth_token_in_IPC)<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}

	printf("2-----in the NVR----\n");
	changeTo(IPC,NVR);
	P2PCommContext *cc_in_NVR=(P2PCommContext *)malloc(sizeof(P2PCommContext));memset(cc_in_NVR,0,sizeof(P2PCommContext));
	P2PCommContext_Conversion(lc_in_NVR, cc_in_NVR);

	P2PAuthToken *p2p_auth_token_in_NVR2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PAuthToken(cc_in_NVR, p2p_auth_token_in_NVR2)<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}
	P2PAuthToken *p2p_auth_token_in_NVR=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_auth_token_in_NVR,p2p_auth_token_in_IPC,sizeof(P2PAuthToken));
	if(HandleP2PAuthToken(cc_in_NVR, p2p_auth_token_in_NVR)<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}

	printf("3-----in the IPC----\n");
	changeTo(NVR, IPC);
	P2PAuthToken *p2p_auth_token_in_IPC2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_auth_token_in_IPC2,p2p_auth_token_in_NVR2,sizeof(P2PAuthToken));
	if(HandleP2PAuthToken(cc_in_IPC, p2p_auth_token_in_IPC2)<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}
	printf("-------------------p2p authentication token finished--------------------\n");


	printf("-------------------p2p reauthentication token begin--------------------\n");
	printf("1-----in the IPC----\n");
	//changeTo(NVR,IPC);

	P2PAuthToken *p2p_reauth_token_IPC1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PReauthToken(cc_in_IPC, p2p_reauth_token_IPC1)<1)
	{
		printf("ProcessP2PReauthToken error\n");
		return 0;
	}

	printf("2-----in the NVR----\n");
	changeTo(IPC,NVR);

	P2PAuthToken *p2p_reauth_token_NVR2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PReauthToken(cc_in_NVR, p2p_reauth_token_NVR2)<1)
	{
		printf("ProcessP2PReauthToken error\n");
		return 0;
	}

	P2PAuthToken *p2p_reauth_token_NVR1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_reauth_token_NVR1,p2p_reauth_token_IPC1,sizeof(P2PAuthToken));
	if(HandleP2PReauthToken(cc_in_NVR, p2p_reauth_token_NVR1)<1)
	{
		printf("HandleP2PReauthToken error\n");
		return 0;
	}

	printf("3-----in the IPC----\n");
	changeTo(NVR, IPC);
	P2PAuthToken *p2p_reauth_token_IPC2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_reauth_token_IPC2,p2p_reauth_token_NVR2,sizeof(P2PAuthToken));
	if(HandleP2PReauthToken(cc_in_IPC, p2p_reauth_token_IPC2)<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}
	printf("-------------------p2p reauthentication token finished--------------------\n");



	printf("-------------------p2p ByeSession begin--------------------\n");
	printf("1-----in the IPC----\n");
	//changeTo(NVR,IPC);

	P2PAuthToken *p2p_bye_session_token_IPC1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PByeSessionToken(cc_in_IPC, p2p_bye_session_token_IPC1)<1)
	{
		printf("ProcessP2PByeSessionToken error\n");
		return 0;
	}

	printf("2-----in the NVR----\n");
	changeTo(IPC,NVR);

	P2PAuthToken *p2p_bye_session_token_NVR1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PByeSessionToken(cc_in_NVR, p2p_bye_session_token_NVR1)<1)
	{
		printf("ProcessP2PByeSessionToken error\n");
		return 0;
	}

	P2PAuthToken *p2p_bye_session_token_NVR2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_bye_session_token_NVR2,p2p_bye_session_token_IPC1,sizeof(P2PAuthToken));
	if(HandleP2PByeSessionToken(cc_in_NVR, p2p_bye_session_token_NVR2)<1)
	{
		printf("HandleP2PByeSessionToken error\n");
		return 0;
	}

	printf("3-----in the IPC----\n");
	changeTo(NVR, IPC);
	P2PAuthToken *p2p_bye_session_token_IPC2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_bye_session_token_IPC2,p2p_bye_session_token_NVR1,sizeof(P2PAuthToken));
	if(HandleP2PByeSessionToken(cc_in_IPC, p2p_bye_session_token_IPC2)<1)
	{
		printf("HandleP2PByeSessionToken error\n");
		return 0;
	}
	printf("-------------------p2p ByeSession finished--------------------\n");




	printf("-------------------p2p ByeLink begin--------------------\n");
	printf("1-----in the IPC----\n");
	//changeTo(NVR,IPC);

	P2PAuthToken *p2p_bye_link_token_IPC1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PByeLinkToken(cc_in_IPC, p2p_bye_link_token_IPC1)<1)
	{
		printf("ProcessP2PByeLinkToken error\n");
		return 0;
	}

	printf("2-----in the NVR----\n");
	changeTo(IPC,NVR);

	P2PAuthToken *p2p_bye_link_token_NVR1=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	if(ProcessP2PByeLinkToken(cc_in_NVR, p2p_bye_link_token_NVR1)<1)
	{
		printf("ProcessP2PByeLinkToken error\n");
		return 0;
	}

	P2PAuthToken *p2p_bye_link_token_NVR2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_bye_link_token_NVR2,p2p_bye_link_token_IPC1,sizeof(P2PAuthToken));
	if(HandleP2PByeLinkToken(cc_in_NVR, p2p_bye_link_token_NVR2)<1)
	{
		printf("HandleP2PByeLinkToken error\n");
		return 0;
	}

	printf("3-----in the IPC----\n");
	changeTo(NVR, IPC);
	P2PAuthToken *p2p_bye_link_token_IPC2=(P2PAuthToken *)malloc(sizeof(P2PAuthToken));
	memcpy(p2p_bye_link_token_IPC2,p2p_bye_link_token_NVR1,sizeof(P2PAuthToken));
	if(HandleP2PByeLinkToken(cc_in_IPC, p2p_bye_link_token_IPC2)<1)
	{
		printf("HandleP2PByeLinkToken error\n");
		return 0;
	}
	printf("-------------------p2p ByeLink finished--------------------\n");


	// step29a/29b: IPC - NVR / NVR - IPC
	//int ProcessP2PByeLinkToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_link_token);
	// step30: IPC/NVR
	//int HandleP2PByeLinkToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_link_token);

	printf("----------------------------p2p communicate finished---------------------------------\n");

return 1;
}

int P2PCommContext_Conversion(P2PLinkContext *lc,P2PCommContext *cc)
{
	memcpy(cc->self_id,lc->self_id,MAXIDSTRING);
	memcpy(&cc->self_MACaddr,&lc->self_MACaddr,sizeof(cc->self_MACaddr));

	memcpy(cc->peer_id,lc->target_id,MAXIDSTRING);
	cc->peer_type=lc->target_type;
	memcpy(&cc->peer_MACaddr,&lc->target_MACaddr,sizeof(cc->peer_MACaddr));

	return 1;
}

int P2PLinkContext_Conversion_C(RegisterContext *rc, P2PLinkContext *lc, enum DeviceType target_type)
{
	memcpy(lc->self_id,rc->self_id,MAXIDSTRING);
	memcpy(lc->self_MACaddr.macaddr,rc->self_MACaddr.macaddr,sizeof(lc->self_MACaddr.macaddr));

	memcpy(lc->peer_id,rc->peer_id,MAXIDSTRING);
	lc->peer_type=SIPserver;
	memcpy(lc->peer_MACaddr.macaddr,rc->peer_MACaddr.macaddr,sizeof(lc->peer_MACaddr.macaddr));
	memcpy(lc->peer_ip,rc->peer_ip,MAXIDSTRING);

	lc->target_ports.rtp_send=0;
	lc->target_ports.rtcp_send=0;
	lc->target_ports.rtp_recv=0;
	lc->target_ports.rtcp_recv=0;

	lc->target_type=target_type;

	return 1;
	}

int P2PLinkContext_Conversion_S(RegisterContext *rc_IPC, RegisterContext *rc_NVR, P2PLinkContext *lc_to_IPC, P2PLinkContext *lc_to_NVR)
{
	memcpy(lc_to_IPC->self_id,rc_IPC->self_id,MAXIDSTRING);
	memcpy(lc_to_IPC->self_MACaddr.macaddr,rc_IPC->self_MACaddr.macaddr,sizeof(lc_to_IPC->self_MACaddr.macaddr));

	memcpy(lc_to_IPC->peer_id,rc_IPC->peer_id,MAXIDSTRING);
	lc_to_IPC->peer_type=IPC;
	memcpy(lc_to_IPC->peer_MACaddr.macaddr,rc_IPC->peer_MACaddr.macaddr,sizeof(lc_to_IPC->peer_MACaddr.macaddr));
	memcpy(lc_to_IPC->peer_ip,rc_IPC->peer_ip,MAXIDSTRING);

	memcpy(lc_to_IPC->target_id,rc_NVR->peer_id,MAXIDSTRING);
	lc_to_IPC->target_type=NVR;
	memcpy(lc_to_IPC->target_MACaddr.macaddr,rc_NVR->peer_MACaddr.macaddr,sizeof(lc_to_IPC->target_MACaddr.macaddr));
	memcpy(lc_to_IPC->target_ip,rc_NVR->peer_ip,MAXIDSTRING);
	lc_to_IPC->target_ports.rtp_send=0;
	lc_to_IPC->target_ports.rtcp_send=0;
	lc_to_IPC->target_ports.rtp_recv=0;
	lc_to_IPC->target_ports.rtcp_recv=0;

	memcpy(lc_to_NVR->self_id,rc_NVR->self_id,MAXIDSTRING);
	memcpy(lc_to_NVR->self_MACaddr.macaddr,rc_NVR->self_MACaddr.macaddr,sizeof(lc_to_NVR->self_MACaddr.macaddr));

	memcpy(lc_to_NVR->peer_id,rc_NVR->peer_id,MAXIDSTRING);
	lc_to_NVR->peer_type=NVR;
	memcpy(lc_to_NVR->peer_MACaddr.macaddr,rc_NVR->peer_MACaddr.macaddr,sizeof(lc_to_NVR->peer_MACaddr.macaddr));
	memcpy(lc_to_NVR->peer_ip,rc_NVR->peer_ip,MAXIDSTRING);

	memcpy(lc_to_NVR->target_id,rc_IPC->peer_id,MAXIDSTRING);
	lc_to_NVR->target_type=IPC;
	memcpy(lc_to_NVR->target_MACaddr.macaddr,rc_IPC->peer_MACaddr.macaddr,sizeof(lc_to_NVR->target_MACaddr.macaddr));
	memcpy(lc_to_NVR->target_ip,rc_IPC->peer_ip,MAXIDSTRING);

	lc_to_NVR->target_ports.rtp_send=0;
	lc_to_NVR->target_ports.rtcp_send=0;
	lc_to_NVR->target_ports.rtp_recv=0;
	lc_to_NVR->target_ports.rtcp_recv=0;

	return 1;
	}

int changeTo(enum DeviceType from_type,enum DeviceType to_type)
{
	if(from_type==IPC)
	{
		memcpy(&KeyboxIPC,&Keybox,sizeof(KeyboxNVR));
		memcpy(&SecurelinksIPC,&Securelinks,sizeof(SecurelinksIPC));

	}
	else if(from_type==NVR)
	{
		memcpy(&KeyboxNVR,&Keybox,sizeof(KeyboxIPC));
		memcpy(&SecurelinksNVR,&Securelinks,sizeof(SecurelinksNVR));
	}
	else if(from_type==SIPserver)
	{
			memcpy(&KeyboxSIPserver,&Keybox,sizeof(KeyboxSIPserver));
			memcpy(&SecurelinksSIPserver,&Securelinks,sizeof(SecurelinksSIPserver));
		}
	else
	{
		return 0;
	}


	if(to_type==IPC)
	{
		Self_type=IPC;
		memcpy(&Keybox,&KeyboxIPC,sizeof(Keybox));
		memcpy(&Securelinks,&SecurelinksIPC,sizeof(Securelinks));

	}
	else if(to_type==NVR)
	{
		Self_type=NVR;
		memcpy(&Keybox,&KeyboxNVR,sizeof(Keybox));
		memcpy(&Securelinks,&SecurelinksNVR,sizeof(Securelinks));
	}
	else if(to_type==SIPserver)
	{
		Self_type=SIPserver;
		memcpy(&Keybox,&KeyboxSIPserver,sizeof(Keybox));
		memcpy(&Securelinks,&SecurelinksSIPserver,sizeof(Securelinks));
	}
	else
	{
		return 0;
	}

	return 1;
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
int printfx(unsigned char *p, int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		printf("%2x ",p[i]);
	}printf("\n");
	return 1;
	}
